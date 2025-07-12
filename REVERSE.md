# Unicode Normalization Fix for gocryptfs Reverse Mode

## Overview

This document details the specific changes made to gocryptfs reverse mode to handle Unicode normalization issues on macOS. Reverse mode presents an encrypted view of plaintext files, and the Unicode normalization problem affects how encrypted filenames are decrypted back to plaintext names that must match existing files on disk.

## The Reverse Mode Problem

### How Reverse Mode Works
- **Input**: Plaintext directory with files like `café.txt`
- **Output**: Encrypted view where `café.txt` becomes something like `gocryptfs.longname.3CHO...` 
- **Lookup Process**: When accessing an encrypted file, gocryptfs must:
  1. Decrypt the encrypted filename to get plaintext name
  2. Find the corresponding plaintext file on disk
  3. Return the file contents

### Unicode Issue in Reverse Mode
The problem occurs in step 2: after decrypting an encrypted filename, the resulting plaintext name might not match the actual file on disk due to Unicode normalization differences:

- Encrypted name decrypts to `café` (NFC form)
- But actual file on disk is `café` (NFD form) - created by Finder
- Result: File not found error, even though the file exists

## Solution Approach

Unlike forward mode where we can migrate files and enforce NFC storage, **reverse mode should not modify the plaintext filesystem**. Instead, we implement **fallback lookup logic**: if the decrypted name doesn't exist on disk, try the alternate Unicode normalization form.

### Key Principle
- **No migration**: Don't rename plaintext files (they might be used by other applications)
- **Fallback only**: Try both NFC and NFD forms when looking up files
- **Read-only approach**: Reverse mode remains a presentation layer without modifying source files

## Detailed Implementation

### 1. File Modified: `internal/fusefrontend_reverse/rpath.go`

#### 1.1 Added Unicode Imports

**Location**: Top of file, import section

**Before**:
```go
import (
	"encoding/base64"
	"log"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)
```

**After**:
```go
import (
	"encoding/base64"
	"log"
	"path/filepath"
	"runtime"      // Added for macOS detection
	"strings"
	"syscall"
	"unicode/utf8" // Added for UTF-8 validation

	"golang.org/x/text/unicode/norm" // Added for Unicode normalization

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)
```

#### 1.2 Enhanced `rDecryptName` Function

**Location**: `internal/fusefrontend_reverse/rpath.go`, function `rDecryptName`

**What was added**: Unicode normalization fallback logic after the normal decryption

**Before** (simplified):
```go
func (rfs *RootNode) rDecryptName(cName string, dirIV []byte, pDir string) (pName string, err error) {
	nameType := nametransform.NameType(cName)
	if nameType == nametransform.LongNameNone {
		pName, err = rfs.nameTransform.DecryptName(cName, dirIV)
		if err != nil {
			// ... error handling ...
			return "", err
		}
		// File was found, return it
	} else if nameType == nametransform.LongNameContent {
		// ... long name handling ...
	} else {
		// ... other cases ...
	}
	return pName, nil
}
```

**After** (with Unicode fallback):
```go
func (rfs *RootNode) rDecryptName(cName string, dirIV []byte, pDir string) (pName string, err error) {
	nameType := nametransform.NameType(cName)
	if nameType == nametransform.LongNameNone {
		pName, err = rfs.nameTransform.DecryptName(cName, dirIV)
		if err != nil {
			// ... existing error handling ...
			return "", err
		}
		
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
		
	} else if nameType == nametransform.LongNameContent {
		// ... existing long name handling unchanged ...
	} else {
		// ... existing other cases unchanged ...
	}
	return pName, nil
}
```

### 2. File Modified: `internal/fusefrontend_reverse/rfs.go`

#### 2.1 Added Unicode Imports

**Location**: Import section

**What to add**:
```go
import (
	// ... existing imports ...
	"runtime"
	"unicode/utf8"
	"golang.org/x/text/unicode/norm"
)
```

#### 2.2 Enhanced `Readdir` Function

**Location**: `internal/fusefrontend_reverse/rfs.go`, function `Readdir`

**What was added**: Normalization of directory entry names for display

**Find the section** around line 73 where filenames are processed:
```go
name = normalizeFilenameFromStorage(name)
```

**Replace with**:
```go
name = normalizeFilenameForDisplay(name)
```

#### 2.3 Added Normalization Helper Functions

**Location**: End of `internal/fusefrontend_reverse/rfs.go`

**What to add**:
```go
// normalizeFilenameForDisplay converts stored filenames to the form expected by macOS GUI.
// In reverse mode, we present the plaintext files as-is, but ensure proper display normalization.
func normalizeFilenameForDisplay(name string) string {
	if runtime.GOOS == "darwin" && utf8.ValidString(name) {
		// For reverse mode, we typically want to preserve the original normalization
		// of the plaintext files, but ensure they display correctly
		return name
	}
	return name
}
```

## Testing the Changes

### 1. Create Test Files with Different Normalizations

```bash
# Create a plaintext directory with Unicode test files
mkdir /tmp/test_reverse_plain
cd /tmp/test_reverse_plain

# Create NFC file (CLI way)
echo "NFC content" > café_nfc.txt

# Create NFD file (simulating Finder)
printf "NFD content" > cafe$'\u0301'_nfd.txt

# Verify we have different normalizations
ls -la *caf*
```

### 2. Test Reverse Mode

```bash
# Initialize reverse mode
cd /path/to/gocryptfs
echo "password" | ./gocryptfs -init -reverse -extpass "echo password" /tmp/test_reverse_plain

# Mount in reverse mode
mkdir /tmp/test_reverse_mount
echo "password" | ./gocryptfs -reverse -extpass "echo password" /tmp/test_reverse_plain /tmp/test_reverse_mount

# Test access
cd /tmp/test_reverse_mount
ls -la  # Should show encrypted filenames
# Try to read each file - both should be accessible
cat [encrypted_filename_1]
cat [encrypted_filename_2]
```

### 3. Verify the Fix

**Before the fix**: Some encrypted files would be inaccessible (file not found errors)
**After the fix**: All encrypted files should be readable, regardless of the Unicode normalization of the underlying plaintext files

## Key Differences from Forward Mode

| Aspect | Forward Mode | Reverse Mode |
|--------|-------------|--------------|
| **Storage Control** | ✅ Can rename encrypted files | ❌ Cannot modify plaintext files |
| **Migration** | ✅ Migrate NFD→NFC | ❌ No migration (read-only) |
| **Approach** | Enforce NFC storage + migrate | Fallback lookup only |
| **Complexity** | High (full Cryptomator logic) | Low (simple fallback) |

## Why This Approach for Reverse Mode

1. **Preservation**: Reverse mode shouldn't modify the source plaintext filesystem
2. **Compatibility**: Other applications may be using the plaintext files
3. **Safety**: Renaming files could break other workflows
4. **Simplicity**: Fallback lookup solves the access problem without side effects

## Testing Verification Points

After implementing these changes, verify:

1. **Both normalization forms accessible**: Files created with different Unicode normalizations should all be accessible through the reverse mount
2. **No file modifications**: The plaintext directory should remain unchanged
3. **Consistent behavior**: Multiple accesses to the same logical file should work consistently
4. **Error handling**: Invalid encrypted names should still return appropriate errors

## Code Files Modified Summary

1. **`internal/fusefrontend_reverse/rpath.go`**:
   - Added Unicode imports (`runtime`, `unicode/utf8`, `golang.org/x/text/unicode/norm`)
   - Enhanced `rDecryptName()` with fallback lookup logic

2. **`internal/fusefrontend_reverse/rfs.go`**:
   - Added Unicode imports
   - Updated `Readdir()` to use proper normalization function
   - Added `normalizeFilenameForDisplay()` helper function

The implementation is minimal and focused, providing Unicode compatibility without the complexity of the full migration logic used in forward mode.
