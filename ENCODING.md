# Unicode Normalization Fix for gocryptfs on macOS

## 1. The Problem

### Background
On macOS, there is a fundamental mismatch between how different applications handle Unicode normalization for filenames containing accented characters (like "café"):

- **Command-line tools** (ls, touch, cat, etc.) typically use **NFC** (Canonical Composed) form: `café` = `c` + `a` + `f` + `é` (4 characters, where `é` is U+00E9)
- **GUI applications** (Finder, TextEdit, etc.) use **NFD** (Canonical Decomposed) form: `café` = `c` + `a` + `f` + `e` + `́` (5 characters, where `é` = `e` + combining acute accent U+0301)

### The Issue
This causes serious usability problems in gocryptfs on macOS:

1. **Duplicate files**: A file created via CLI as "café.txt" (NFC) would appear different from "café.txt" created via Finder (NFD), even though they look identical to users
2. **Invisible files**: Files created by CLI tools would not appear in Finder, and vice versa
3. **Access failures**: TextEdit couldn't open files created by `touch`, and `cat` couldn't read files created by Finder
4. **Broken workflows**: Users couldn't seamlessly work with the same files using both GUI and CLI tools

### Technical Details
The problem occurred because gocryptfs was treating NFC and NFD forms as completely different filenames:
- CLI: `touch "café.txt"` → stores as NFC internally
- Finder: creates "café.txt" → stores as NFD internally  
- Result: Two different encrypted files for what users perceive as the same filename

## 2. Solution Logic (Cryptomator-Inspired Approach)

### Core Principles
I adopted the approach used by [Cryptomator](https://github.com/cryptomator/cryptomator), a mature encrypted filesystem that solved this exact problem, and more specifically described [here](https://github.com/cryptomator/cryptomator/issues/264):

1. **Canonical Storage**: Always store filenames internally in NFC (composed) form for consistency
2. **Transparent Lookup**: When looking up a file, try both NFC and NFD forms to find existing files
3. **Migration**: If an NFD file exists but no NFC equivalent, migrate the NFD file to NFC
4. **Platform-Appropriate Display**: Return directory listings in the form expected by the OS (NFD on macOS for GUI compatibility)

### Why This Approach Works
- **Prevents duplicates**: Only one canonical form (NFC) is stored
- **Maintains compatibility**: Files created by any application (CLI or GUI) can be accessed by any other application
- **Transparent to users**: Users see consistent behavior regardless of which tool they use
- **Backward compatible**: Existing NFD files are automatically migrated to NFC when accessed

### Algorithm Flow
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

## 3. Detailed Implementation

### 3.1 Normalization Functions

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

### 3.2 File Creation Operations

Updated all file creation operations to normalize input to NFC:

**Files**: `internal/fusefrontend/node_open_create.go`
```go
func (n *Node) Create(ctx context.Context, name string, ...) {
    name = normalizeFilename(name)  // Always store as NFC
    // ... rest of creation logic
}
```

**Directories**: `internal/fusefrontend/node_dir_ops.go`
```go
func (n *Node) Mkdir(ctx context.Context, name string, ...) {
    name = normalizeFilename(name)  // Always store as NFC
    // ... rest of creation logic
}
```

**Symlinks, Device nodes, Hard links**: `internal/fusefrontend/node.go`
```go
func (n *Node) Symlink/Mknod/Link(..., name string, ...) {
    name = normalizeFilename(name)  // Always store as NFC
    // ... rest of creation logic
}
```

### 3.3 Lookup with Fallback and Migration

The core innovation is in `internal/fusefrontend/node_prepare_syscall.go`. I completely rewrote the `prepareAtSyscall` function to implement Cryptomator's lookup logic:

```go
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
    // ... validation ...
    
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

### 3.4 Migration Logic

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
    // ... handle encryption of both old and new names ...
    return syscallcompat.Renameat(dirfd, oldCName, dirfd, newCName)
}
```

### 3.5 Directory Listing

Updated `Readdir` in `internal/fusefrontend/node_dir_ops.go` to return NFD for macOS GUI compatibility:

```go
func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
    // ... read and decrypt directory entries ...
    
    // Convert from storage format (NFC) to OS-expected format
    name = normalizeFilenameForDisplay(name)  // NFC → NFD on macOS
    
    // ... return directory entries ...
}
```

### 3.6 Other File Operations

Updated all other file operations to use NFC for lookups:
- `Unlink`: normalize filename before deletion
- `Rmdir`: normalize directory name before deletion  
- `Rename`: normalize both old and new names

### 3.7 Reverse Mode Implementation

For reverse mode (`internal/fusefrontend_reverse/rpath.go`), we implemented fallback lookup without migration (since reverse mode shouldn't modify plaintext files):

```go
func (rfs *RootNode) rDecryptName(cName string, dirIV []byte, pDir string) (pName string, err error) {
    // ... decrypt name ...
    
    // On macOS, try alternate Unicode form if file doesn't exist
    if runtime.GOOS == "darwin" && utf8.ValidString(pName) {
        pPath := filepath.Join(rfs.args.Cipherdir, pDir, pName)
        if statErr := syscall.Stat(pPath, &st); statErr != nil {
            // Try alternate form (NFC ↔ NFD)
            alternateName := getAlternateForm(pName)
            alternatePath := filepath.Join(rfs.args.Cipherdir, pDir, alternateName)
            if syscall.Stat(alternatePath, &altSt) == nil {
                return alternateName, nil  // Use alternate form
            }
        }
    }
    
    return pName, nil
}
```

## 4. Platform Compatibility

The implementation is macOS-specific (guarded by `runtime.GOOS == "darwin"`) because:
- Linux typically uses UTF-8 without normalization issues
- Windows uses UTF-16 with different Unicode handling
- Only macOS has the CLI/GUI normalization split that causes this problem

This fix ensures that gocryptfs provides seamless Unicode filename handling on macOS, matching the behavior users expect from a native filesystem.
