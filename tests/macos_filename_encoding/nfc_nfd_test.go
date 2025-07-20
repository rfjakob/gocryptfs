package macos_filename_encoding

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var nfcName = norm.NFC.String("e\u0301") // é
var nfdName = norm.NFD.String("e\u0301") // e + combining acute accent

// Additional test cases with various Unicode characters
var unicodeTestCases = []struct {
	name    string
	nfc     string
	nfd     string
	comment string
}{
	{"acute_e", norm.NFC.String("e\u0301"), norm.NFD.String("e\u0301"), "é (e + combining acute)"},
	{"circumflex_a", norm.NFC.String("a\u0302"), norm.NFD.String("a\u0302"), "â (a + combining circumflex)"},
	{"tilde_n", norm.NFC.String("n\u0303"), norm.NFD.String("n\u0303"), "ñ (n + combining tilde)"},
	{"umlaut_u", norm.NFC.String("u\u0308"), norm.NFD.String("u\u0308"), "ü (u + combining diaeresis)"},
	{"multiple_combining", norm.NFC.String("o\u0302\u0308"), norm.NFD.String("o\u0302\u0308"), "ô̈ (o + circumflex + diaeresis)"},
}

func TestCreateNFC_AccessNFD(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}
	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create a file with an NFC name
	nfcPath := filepath.Join(mntDir, nfcName)
	err := os.WriteFile(nfcPath, []byte("content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with NFC name: %v", err)
	}

	// Try to read it with an NFD name
	nfdPath := filepath.Join(mntDir, nfdName)
	content, err := os.ReadFile(nfdPath)
	if err != nil {
		t.Fatalf("Failed to read file with NFD name: %v", err)
	}
	if string(content) != "content" {
		t.Errorf("Wrong content: %q", string(content))
	}
}

func TestCreateNFD_AccessNFC(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}
	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create a file with an NFD name
	nfdPath := filepath.Join(mntDir, nfdName)
	err := os.WriteFile(nfdPath, []byte("content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with NFD name: %v", err)
	}

	// Try to read it with an NFC name
	nfcPath := filepath.Join(mntDir, nfcName)
	content, err := os.ReadFile(nfcPath)
	if err != nil {
		t.Fatalf("Failed to read file with NFC name: %v", err)
	}
	if string(content) != "content" {
		t.Errorf("Wrong content: %q", string(content))
	}
}

// TestMultipleUnicodeCharacters tests various Unicode characters with different NFC/NFD forms
func TestMultipleUnicodeCharacters(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}

	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	for _, tc := range unicodeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.nfc == tc.nfd {
				t.Skipf("NFC and NFD are identical for %s", tc.comment)
			}

			// Create with NFC, access with NFD
			nfcPath := filepath.Join(mntDir, "nfc_"+tc.nfc+".txt")
			err := os.WriteFile(nfcPath, []byte("nfc_content"), 0600)
			if err != nil {
				t.Fatalf("Failed to create file with NFC name %s: %v", tc.comment, err)
			}

			nfdPath := filepath.Join(mntDir, "nfc_"+tc.nfd+".txt")
			content, err := os.ReadFile(nfdPath)
			if err != nil {
				t.Fatalf("Failed to read file with NFD name %s: %v", tc.comment, err)
			}
			if string(content) != "nfc_content" {
				t.Errorf("Wrong content for %s: got %q, want %q", tc.comment, string(content), "nfc_content")
			}

			// Create with NFD, access with NFC
			nfdPath2 := filepath.Join(mntDir, "nfd_"+tc.nfd+".txt")
			err = os.WriteFile(nfdPath2, []byte("nfd_content"), 0600)
			if err != nil {
				t.Fatalf("Failed to create file with NFD name %s: %v", tc.comment, err)
			}

			nfcPath2 := filepath.Join(mntDir, "nfd_"+tc.nfc+".txt")
			content, err = os.ReadFile(nfcPath2)
			if err != nil {
				t.Fatalf("Failed to read file with NFC name %s: %v", tc.comment, err)
			}
			if string(content) != "nfd_content" {
				t.Errorf("Wrong content for %s: got %q, want %q", tc.comment, string(content), "nfd_content")
			}
		})
	}
}

// TestDirectoryOperations tests directory creation and listing with NFC/NFD names
func TestDirectoryOperations(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}

	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create directory with NFC name
	nfcDirPath := filepath.Join(mntDir, "dir_"+nfcName)
	err := os.Mkdir(nfcDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory with NFC name: %v", err)
	}

	// Access with NFD name
	nfdDirPath := filepath.Join(mntDir, "dir_"+nfdName)
	stat, err := os.Stat(nfdDirPath)
	if err != nil {
		t.Fatalf("Failed to stat directory with NFD name: %v", err)
	}
	if !stat.IsDir() {
		t.Error("Expected directory, got file")
	}

	// Create file inside directory using NFD path
	filePath := filepath.Join(nfdDirPath, "test.txt")
	err = os.WriteFile(filePath, []byte("dir_content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file in directory: %v", err)
	}

	// Read file using NFC directory path
	filePath2 := filepath.Join(nfcDirPath, "test.txt")
	content, err := os.ReadFile(filePath2)
	if err != nil {
		t.Fatalf("Failed to read file from directory: %v", err)
	}
	if string(content) != "dir_content" {
		t.Errorf("Wrong content: got %q, want %q", string(content), "dir_content")
	}

	// Test directory listing
	entries, err := os.ReadDir(nfdDirPath)
	if err != nil {
		t.Fatalf("Failed to list directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "test.txt" {
		t.Errorf("Unexpected directory contents: %v", entries)
	}
}

// TestFileOperations tests various file operations with NFC/NFD names
func TestFileOperations(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}

	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create file with NFC name
	nfcPath := filepath.Join(mntDir, "ops_"+nfcName+".txt")
	err := os.WriteFile(nfcPath, []byte("original"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Test stat with NFD name
	nfdPath := filepath.Join(mntDir, "ops_"+nfdName+".txt")
	stat, err := os.Stat(nfdPath)
	if err != nil {
		t.Fatalf("Failed to stat file with NFD name: %v", err)
	}
	if stat.Size() != 8 {
		t.Errorf("Wrong file size: got %d, want 8", stat.Size())
	}

	// Test truncate with NFD name
	err = os.Truncate(nfdPath, 4)
	if err != nil {
		t.Fatalf("Failed to truncate file: %v", err)
	}

	// Verify truncation with NFC name
	content, err := os.ReadFile(nfcPath)
	if err != nil {
		t.Fatalf("Failed to read truncated file: %v", err)
	}
	if string(content) != "orig" {
		t.Errorf("Wrong content after truncate: got %q, want %q", string(content), "orig")
	}

	// Test chmod with NFD name
	err = os.Chmod(nfdPath, 0644)
	if err != nil {
		t.Fatalf("Failed to chmod file: %v", err)
	}

	// Verify chmod with NFC name
	stat, err = os.Stat(nfcPath)
	if err != nil {
		t.Fatalf("Failed to stat file after chmod: %v", err)
	}
	if stat.Mode().Perm() != 0644 {
		t.Errorf("Wrong permissions: got %o, want %o", stat.Mode().Perm(), 0644)
	}

	// Test removal with NFD name
	err = os.Remove(nfdPath)
	if err != nil {
		t.Fatalf("Failed to remove file with NFD name: %v", err)
	}

	// Verify removal with NFC name
	_, err = os.Stat(nfcPath)
	if !os.IsNotExist(err) {
		t.Error("File should not exist after removal")
	}
}

// TestEdgeCases tests edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}

	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Test filename that is identical in NFC and NFD
	identicalName := "regular_ascii.txt"
	if norm.NFC.String(identicalName) != norm.NFD.String(identicalName) {
		t.Fatal("Test setup error: filename should be identical in NFC and NFD")
	}

	identicalPath := filepath.Join(mntDir, identicalName)
	err := os.WriteFile(identicalPath, []byte("identical"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with identical NFC/NFD name: %v", err)
	}

	content, err := os.ReadFile(identicalPath)
	if err != nil {
		t.Fatalf("Failed to read file with identical name: %v", err)
	}
	if string(content) != "identical" {
		t.Errorf("Wrong content: got %q, want %q", string(content), "identical")
	}

	// Test invalid UTF-8 bytes (should fall back to direct access)
	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
	invalidPath := filepath.Join(mntDir, invalidUTF8)
	err = os.WriteFile(invalidPath, []byte("invalid_utf8"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with invalid UTF-8 name: %v", err)
	}

	content, err = os.ReadFile(invalidPath)
	if err != nil {
		t.Fatalf("Failed to read file with invalid UTF-8 name: %v", err)
	}
	if string(content) != "invalid_utf8" {
		t.Errorf("Wrong content: got %q, want %q", string(content), "invalid_utf8")
	}

	// Test long filename with Unicode characters
	longUnicode := strings.Repeat(nfcName, 50) // 50 repetitions of é
	longPath := filepath.Join(mntDir, longUnicode+".txt")
	err = os.WriteFile(longPath, []byte("long_unicode"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file with long Unicode name: %v", err)
	}

	// Access with NFD version
	longNFD := strings.Repeat(nfdName, 50)
	longNFDPath := filepath.Join(mntDir, longNFD+".txt")
	content, err = os.ReadFile(longNFDPath)
	if err != nil {
		t.Fatalf("Failed to read file with long NFD name: %v", err)
	}
	if string(content) != "long_unicode" {
		t.Errorf("Wrong content: got %q, want %q", string(content), "long_unicode")
	}
}

// TestNonExistentFiles tests behavior when files don't exist in either normalization form
func TestNonExistentFiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}

	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Try to access non-existent file with NFC name
	nonExistentNFC := filepath.Join(mntDir, "nonexistent_"+nfcName+".txt")
	_, err := os.ReadFile(nonExistentNFC)
	if !os.IsNotExist(err) {
		t.Errorf("Expected ENOENT for non-existent NFC file, got: %v", err)
	}

	// Try to access non-existent file with NFD name
	nonExistentNFD := filepath.Join(mntDir, "nonexistent_"+nfdName+".txt")
	_, err = os.ReadFile(nonExistentNFD)
	if !os.IsNotExist(err) {
		t.Errorf("Expected ENOENT for non-existent NFD file, got: %v", err)
	}

	// Create file with specific normalization and ensure only that form exists initially
	specificNFC := filepath.Join(mntDir, "specific_"+nfcName+".txt")
	err = os.WriteFile(specificNFC, []byte("content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Now both forms should work due to Unicode normalization fallback
	specificNFD := filepath.Join(mntDir, "specific_"+nfdName+".txt")
	_, err = os.ReadFile(specificNFD)
	if err != nil {
		t.Errorf("NFD access should work after NFC creation: %v", err)
	}
}

// TestNestedDirectories tests Unicode normalization in nested directory structures
func TestNestedDirectories(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only test")
	}
	if nfcName == nfdName {
		t.Fatal("NFC and NFD names should be different")
	}

	test_helpers.ResetTmpDir(false)
	cipherDir := test_helpers.InitFS(t)
	mntDir := filepath.Join(test_helpers.TmpDir, "mnt")
	test_helpers.MountOrFatal(t, cipherDir, mntDir, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(mntDir)

	// Create nested directory structure with mixed NFC/NFD
	dir1NFC := filepath.Join(mntDir, "level1_"+nfcName)
	err := os.Mkdir(dir1NFC, 0755)
	if err != nil {
		t.Fatalf("Failed to create level1 directory: %v", err)
	}

	// Create subdirectory using NFD path to parent
	dir1NFD := filepath.Join(mntDir, "level1_"+nfdName)
	dir2Path := filepath.Join(dir1NFD, "level2_"+nfdName)
	err = os.Mkdir(dir2Path, 0755)
	if err != nil {
		t.Fatalf("Failed to create level2 directory: %v", err)
	}

	// Create file in nested structure using NFC path
	dir2NFC := filepath.Join(dir1NFC, "level2_"+nfcName)
	filePath := filepath.Join(dir2NFC, "nested_file.txt")
	err = os.WriteFile(filePath, []byte("nested_content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create nested file: %v", err)
	}

	// Access file using different path combinations
	filePath2 := filepath.Join(dir2Path, "nested_file.txt") // NFD/NFD path
	content, err := os.ReadFile(filePath2)
	if err != nil {
		t.Fatalf("Failed to read nested file with NFD path: %v", err)
	}
	if string(content) != "nested_content" {
		t.Errorf("Wrong content: got %q, want %q", string(content), "nested_content")
	}

	// Test directory traversal with mixed normalization
	entries, err := os.ReadDir(dir1NFD)
	if err != nil {
		t.Fatalf("Failed to list level1 directory: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry in level1, got %d", len(entries))
	}

	entries, err = os.ReadDir(dir2NFC)
	if err != nil {
		t.Fatalf("Failed to list level2 directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "nested_file.txt" {
		t.Errorf("Unexpected level2 contents: %v", entries)
	}
}
