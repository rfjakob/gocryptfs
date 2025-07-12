# macOS Compatibility Improvements for gocryptfs

This document describes the major changes made to improve gocryptfs compatibility on macOS, addressing critical issues with Unicode filename handling and directory listing functionality.

## 1. Unicode Normalization Fix for Forward Mode

### Problem Statement

On macOS, there is a fundamental mismatch between how different applications handle Unicode normalization for filenames containing accented characters (like "café"):

- **Command-line tools** (ls, touch, cat, etc.) typically use **NFC** (Canonical Composed) form: `café` = `c` + `a` + `f` + `é` (4 characters, where `é` is U+00E9)
- **GUI applications** (Finder, TextEdit, etc.) use **NFD** (Canonical Decomposed) form: `café` = `c` + `a` + `f` + `e` + `́` (5 characters, where `é` = `e` + combining acute accent U+0301)

This caused serious usability problems in gocryptfs on macOS:

1. **Duplicate files**: A file created via CLI as "café.txt" (NFC) would appear different from "café.txt" created via Finder (NFD), even though they look identical to users
2. **Invisible files**: Files created by CLI tools would not appear in Finder, and vice versa
3. **Access failures**: TextEdit couldn't open files created by `touch`, and `cat` couldn't read files created by Finder
4. **Broken workflows**: Users couldn't seamlessly work with the same files using both GUI and CLI tools

### Solution: Cryptomator-Inspired Approach

The implementation adopts the approach used by [Cryptomator](https://github.com/cryptomator/cryptomator), specifically described [here](https://github.com/cryptomator/cryptomator/issues/264):

#### Core Principles
1. **Canonical Storage**: Always store filenames internally in NFC (composed) form for consistency
2. **Transparent Lookup**: When looking up a file, try both NFC and NFD forms to find existing files
3. **Migration**: If an NFD file exists but no NFC equivalent, migrate the NFD file to NFC
4. **Platform-Appropriate Display**: Return directory listings in the form expected by the OS (NFD on macOS for GUI compatibility)

#### Algorithm Flow
```
File Creation (Create, Mkdir, Symlink, etc.):
Input filename → Normalize to NFC → Store with NFC name

File Lookup (Lookup, Open, Stat, etc.):
Input filename → Try NFC lookup
  ↓ If found: return file
  ↓ If not found: try NFD lookup
    ↓ If NFD found: migrate NFD→NFC, return file
    ↓ If neither found: return ENOENT

Directory Listing (Readdir):
Stored NFC names → Convert to NFD for display on macOS
```

### Implementation Details

#### Normalization Functions
Added core normalization functions in `internal/fusefrontend/node_dir_ops.go`:

```go
// normalizeFilename converts filenames to NFC for consistent internal storage
func normalizeFilename(name string) string {
    if runtime.GOOS == "darwin" && utf8.ValidString(name) {
        return norm.NFC.String(name)
    }
    return name
}

// normalizeFilenameForDisplay converts NFC to NFD for macOS GUI compatibility
func normalizeFilenameForDisplay(name string) string {
    if runtime.GOOS == "darwin" && utf8.ValidString(name) {
        return norm.NFD.String(name)
    }
    return name
}
```

#### File Creation Operations
Updated all file creation operations to normalize input to NFC:

- **Files**: `internal/fusefrontend/node_open_create.go`
- **Directories**: `internal/fusefrontend/node_dir_ops.go`
- **Symlinks, Device nodes, Hard links**: `internal/fusefrontend/node.go`

#### Lookup with Fallback and Migration
The core innovation is in `internal/fusefrontend/node_prepare_syscall.go`. Completely rewrote the `prepareAtSyscall` function to implement Cryptomator's lookup logic:

```go
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
    if runtime.GOOS == "darwin" && utf8.ValidString(child) {
        // Step 1: Always try NFC first (canonical storage form)
        normalizedChild := norm.NFC.String(child)
        dirfd, cName, errno = n.prepareAtSyscallDirect(normalizedChild)
        if errno == 0 {
            return dirfd, cName, 0  // Found NFC version
        }
        
        // Step 2: Try alternate form if input was different
        if normalizedChild != child {
            // Input was NFD, try original NFD form
            dirfdNFD, cNameNFD, errnoNFD := n.prepareAtSyscallDirect(child)
            if errnoNFD == 0 {
                // Found NFD file - migrate it to NFC
                if errno := n.migrateFilename(child, normalizedChild); errno == 0 {
                    return n.prepareAtSyscallDirect(normalizedChild)  // Use migrated NFC
                } else {
                    return dirfdNFD, cNameNFD, 0  // Migration failed, use NFD
                }
            }
        }
        
        // Step 3: If input was NFC, also try NFD as fallback
        if normalizedChild == child {
            nfdChild := norm.NFD.String(child)
            if nfdChild != child {
                dirfdNFD, cNameNFD, errnoNFD := n.prepareAtSyscallDirect(nfdChild)
                if errnoNFD == 0 {
                    // Found NFD file - migrate it to NFC
                    if errno := n.migrateFilename(nfdChild, normalizedChild); errno == 0 {
                        return n.prepareAtSyscallDirect(normalizedChild)
                    } else {
                        return dirfdNFD, cNameNFD, 0
                    }
                }
            }
        }
    }
    
    return n.prepareAtSyscallDirect(child)  // Non-macOS or fallback
}
```

#### Migration Logic
The `migrateFilename` function handles moving NFD files to NFC:

```go
func (n *Node) migrateFilename(oldName, newName string) syscall.Errno {
    if oldName == newName {
        return 0  // Nothing to do
    }
    
    // For plaintext names: simple rename
    if rn.args.PlaintextNames {
        return syscallcompat.Renameat(dirfd, oldName, dirfd, newName)
    }
    
    // For encrypted names: encrypt both names and rename
    return syscallcompat.Renameat(dirfd, oldCName, dirfd, newCName)
}
```

#### Directory Listing
Updated `Readdir` in `internal/fusefrontend/node_dir_ops.go` to return NFD for macOS GUI compatibility:

```go
func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
    // ... read and decrypt directory entries ...
    
    // Convert from storage format (NFC) to OS-expected format
    name = normalizeFilenameForDisplay(name)  // NFC → NFD on macOS
    
    // ... return directory entries ...
}
```

### Files Modified
- `internal/fusefrontend/node_prepare_syscall.go`: Core lookup and migration logic
- `internal/fusefrontend/node_dir_ops.go`: Normalization functions and directory operations
- `internal/fusefrontend/node_open_create.go`: File creation normalization
- `internal/fusefrontend/node.go`: Symlink/device/hardlink normalization

## 2. Unicode Normalization Fix for Reverse Mode

### Problem in Reverse Mode

Reverse mode presents an encrypted view of plaintext files. The Unicode normalization problem affects how encrypted filenames are decrypted back to plaintext names that must match existing files on disk.

After decrypting an encrypted filename, the resulting plaintext name might not match the actual file on disk due to Unicode normalization differences:
- Encrypted name decrypts to `café` (NFC form)
- But actual file on disk is `café` (NFD form) - created by Finder
- Result: File not found error, even though the file exists

### Solution Approach

Unlike forward mode, **reverse mode should not modify the plaintext filesystem**. Instead, we implement **fallback lookup logic**: if the decrypted name doesn't exist on disk, try the alternate Unicode normalization form.

#### Key Principles
- **No migration**: Don't rename plaintext files (they might be used by other applications)
- **Fallback only**: Try both NFC and NFD forms when looking up files
- **Read-only approach**: Reverse mode remains a presentation layer without modifying source files

### Implementation

#### Enhanced `rDecryptName` Function
In `internal/fusefrontend_reverse/rpath.go`, added Unicode normalization fallback logic:

```go
func (rfs *RootNode) rDecryptName(cName string, dirIV []byte, pDir string) (pName string, err error) {
    // ... existing decryption logic ...
    
    // NEW: On macOS, handle Unicode normalization fallback
    if runtime.GOOS == "darwin" && utf8.ValidString(pName) {
        // Check if the decrypted name actually exists on disk
        pPath := filepath.Join(rfs.args.Cipherdir, pDir, pName)
        var st syscall.Stat_t
        if statErr := syscall.Stat(pPath, &st); statErr != nil {
            // Try the alternate Unicode form
            var alternateName string
            if norm.NFC.String(pName) == pName {
                // pName is NFC, try NFD
                alternateName = norm.NFD.String(pName)
            } else {
                // pName is NFD (or mixed), try NFC
                alternateName = norm.NFC.String(pName)
            }
            
            if alternateName != pName {
                alternatePath := filepath.Join(rfs.args.Cipherdir, pDir, alternateName)
                var altSt syscall.Stat_t
                if altStatErr := syscall.Stat(alternatePath, &altSt); altStatErr == nil {
                    // The alternate form exists, use it
                    return alternateName, nil
                }
            }
        }
    }
    
    return pName, nil
}
```

### Key Differences from Forward Mode

| Aspect | Forward Mode | Reverse Mode |
|--------|-------------|--------------|
| **Storage Control** | ✅ Can rename encrypted files | ❌ Cannot modify plaintext files |
| **Migration** | ✅ Migrate NFD→NFC | ❌ No migration (read-only) |
| **Approach** | Enforce NFC storage + migrate | Fallback lookup only |
| **Complexity** | High (full Cryptomator logic) | Low (simple fallback) |

### Files Modified
- `internal/fusefrontend_reverse/rpath.go`: Added Unicode imports and enhanced `rDecryptName()` with fallback lookup logic
- `internal/fusefrontend_reverse/node_dir_ops.go`: Added Unicode imports and helper functions

## 3. Directory Stream Implementation - macOS Compatibility Fix

### Problem Discovery

During the implementation of Unicode normalization, we discovered a critical bug in directory listing functionality. While file operations worked correctly, directory listings (via `ls`, Finder, etc.) would show empty directories even when files were present.

#### Symptoms
- Files could be created, read, written, and deleted successfully
- File operations via direct path access worked normally
- Directory listings (`ls`, `find`, Finder) showed empty directories
- The underlying encrypted directory contained the expected files
- Raw Go directory reading worked correctly

### Root Cause Analysis

The issue was traced to incompatibility between the go-fuse library's `NewLoopbackDirStreamFd` function and macOS/APFS filesystem behavior:

1. **Raw directory reading worked**: Using Go's standard `os.File.Readdirnames()` could successfully read directory entries
2. **go-fuse loopback stream failed**: `fs.NewLoopbackDirStreamFd()` consistently returned `nil` entries immediately, indicating "end of directory"
3. **File descriptor ownership issues**: The loopback stream appeared to take ownership of file descriptors in a way that conflicted with macOS directory access patterns

#### Why This Affects macOS Specifically
1. **APFS vs ext4/xfs differences**: macOS uses APFS which has different directory iteration semantics compared to Linux filesystems
2. **Darwin syscall differences**: macOS implements POSIX directory operations with subtle differences that affect low-level libraries
3. **go-fuse library testing**: The go-fuse library is primarily developed and tested on Linux, with less comprehensive macOS testing

### Solution: Platform-Specific Directory Stream

Implemented a custom directory stream that is only used on macOS (`runtime.GOOS == "darwin"`), while maintaining the standard go-fuse loopback implementation on other platforms.

#### Implementation
```go
// Use custom directory stream on macOS due to issues with go-fuse loopback implementation
if runtime.GOOS == "darwin" {
    // On macOS, use our custom directory stream implementation
    // The go-fuse NewLoopbackDirStreamFd has compatibility issues with macOS/APFS
    ds = &customDirStream{fd: fdDup}
    errno = 0
} else {
    // On other platforms, use the standard loopback directory stream
    ds, errno = fs.NewLoopbackDirStreamFd(fdDup)
    if errno != 0 {
        goto err_out
    }
}
```

#### Custom Directory Stream Features
The `customDirStream` struct implements all required interfaces:
- `fs.DirStream` - Core directory stream interface
- `fs.FileReaddirenter` - For reading directory entries
- `fs.FileSeekdirer` - For seeking within directory streams
- `fs.FileReleasedirer` - For cleanup
- `fs.FileFsyncdirer` - For sync operations

Key implementation details:
1. **Lazy Loading**: Directory entries are loaded on first access using `os.File.Readdirnames(-1)`
2. **Proper File Descriptor Management**: Uses the provided file descriptor without taking improper ownership
3. **Seeking Support**: Implements proper seek behavior for directory offsets
4. **Interface Compliance**: Implements all required methods to be a drop-in replacement

### Files Modified
- `internal/fusefrontend/file_dir_ops.go`: Added `runtime` import, modified `OpendirHandle()` to use platform-specific directory streams, implemented `customDirStream` type

## 4. Platform Compatibility

All implementations are macOS-specific (guarded by `runtime.GOOS == "darwin"`) because:
- Linux typically uses UTF-8 without normalization issues
- Windows uses UTF-16 with different Unicode handling
- Only macOS has the CLI/GUI normalization split that causes this problem
- The directory stream issue only affects macOS/APFS
