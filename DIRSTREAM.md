# Directory Stream Implementation - macOS Compatibility Fix

## Problem Description

During the implementation of Unicode normalization for macOS filename compatibility, we discovered a critical bug in directory listing functionality. While file operations worked correctly, directory listings (via `ls`, Finder, etc.) would show empty directories even when files were present.

### Symptoms
- Files could be created, read, written, and deleted successfully
- File operations via direct path access worked normally
- Directory listings (`ls`, `find`, Finder) showed empty directories
- The underlying encrypted directory contained the expected files
- Raw Go directory reading worked correctly

### Root Cause
The issue was traced to incompatibility between the go-fuse library's `NewLoopbackDirStreamFd` function and macOS/APFS filesystem behavior. The debugging process revealed:

1. **Raw directory reading worked**: Using Go's standard `os.File.Readdirnames()` could successfully read directory entries
2. **go-fuse loopback stream failed**: `fs.NewLoopbackDirStreamFd()` consistently returned `nil` entries immediately, indicating "end of directory"
3. **File descriptor ownership issues**: The loopback stream appeared to take ownership of file descriptors in a way that conflicted with macOS directory access patterns

## Technical Analysis

### Why This Affects macOS Specifically

1. **APFS vs ext4/xfs differences**: macOS uses APFS which has different directory iteration semantics compared to Linux filesystems
2. **Darwin syscall differences**: macOS implements POSIX directory operations with subtle differences that affect low-level libraries
3. **go-fuse library testing**: The go-fuse library is primarily developed and tested on Linux, with less comprehensive macOS testing

### File Descriptor Behavior

The debugging showed that:
- Creating fresh file descriptors for each operation worked
- Using duplicated file descriptors with `NewLoopbackDirStreamFd` failed
- The loopback implementation seemed to corrupt or improperly manage the file descriptor state on macOS

## Solution Implementation

### Approach: Platform-Specific Directory Stream

We implemented a custom directory stream that is only used on macOS (`runtime.GOOS == "darwin"`), while maintaining the standard go-fuse loopback implementation on other platforms.

### Code Structure

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

### Custom Directory Stream Implementation

The `customDirStream` struct implements all required interfaces:
- `fs.DirStream` - Core directory stream interface
- `fs.FileReaddirenter` - For reading directory entries
- `fs.FileSeekdirer` - For seeking within directory streams
- `fs.FileReleasedirer` - For cleanup
- `fs.FileFsyncdirer` - For sync operations

#### Key Features:

1. **Lazy Loading**: Directory entries are loaded on first access using `os.File.Readdirnames(-1)`
2. **Proper File Descriptor Management**: Uses the provided file descriptor without taking improper ownership
3. **Seeking Support**: Implements proper seek behavior for directory offsets
4. **Interface Compliance**: Implements all required methods to be a drop-in replacement

#### Implementation Details:

```go
type customDirStream struct {
    fd      int        // File descriptor for the directory
    entries []string   // Cached directory entries
    pos     int        // Current position in entries
}
```

**Loading Strategy**:
- Entries are loaded once on first `Readdirent()` call
- Uses `os.NewFile()` to wrap the file descriptor without taking ownership
- Seeks back to beginning after reading to preserve state
- Caches entries in memory for subsequent access

**Position Management**:
- Tracks current position manually
- Supports seeking to arbitrary offsets
- Returns `nil` entry when at end of directory

## Files Modified

1. **`internal/fusefrontend/file_dir_ops.go`**:
   - Added `runtime` import for OS detection
   - Modified `OpendirHandle()` to use platform-specific directory streams
   - Implemented `customDirStream` type with all required methods
   - Cleaned up debug logging and made code production-ready

## Testing and Validation

### Test Results:
- ✅ Directory listings now work correctly on macOS
- ✅ `ls` command shows all files
- ✅ Finder displays directory contents properly
- ✅ File operations continue to work normally
- ✅ Unicode normalization works as expected
- ✅ Linux/other platforms unaffected (continue using go-fuse loopback)

### Performance Considerations:
- **Memory Usage**: Directory entries are cached in memory per open directory
- **I/O Efficiency**: Single read operation loads all entries (vs. streaming)
- **Compatibility**: Only affects macOS, other platforms maintain existing behavior

## Future Considerations

### Potential Improvements:
1. **Upstream Fix**: Report the issue to go-fuse maintainers for a proper fix
2. **Streaming Implementation**: Implement true streaming if memory usage becomes a concern
3. **Performance Monitoring**: Monitor if the caching approach causes issues with very large directories

### Alternative Approaches Considered:
1. **File Descriptor Recreation**: Tried creating fresh file descriptors for each operation - worked but seemed wasteful
2. **go-fuse Version Upgrade**: Could try newer go-fuse versions, but risk breaking other functionality
3. **Complete Custom Implementation**: Could implement entire FUSE directory handling, but too invasive

## Conclusion

The custom directory stream implementation successfully resolves the macOS directory listing issue while:
- Maintaining compatibility with other platforms
- Preserving all existing functionality
- Providing clean, maintainable code
- Following go-fuse interface patterns

This solution specifically addresses the macOS/APFS incompatibility with go-fuse's loopback directory stream implementation, ensuring that gocryptfs works correctly across all supported platforms.
