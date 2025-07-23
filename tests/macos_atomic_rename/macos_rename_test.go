//go:build darwin
// +build darwin

package macos_atomic_rename

import (
    "os"
    "path/filepath"
    "runtime"
    "testing"

    "golang.org/x/sys/unix"

    "github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
    "github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestRenameExchangeOnGocryptfs tests the core RENAME_EXCHANGE functionality
// on a mounted gocryptfs filesystem - this is the exact fix for issue #914
func TestRenameExchangeOnGocryptfs(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("This test is macOS-specific")
    }

    // Initialize and mount gocryptfs filesystem
    cipherDir := test_helpers.InitFS(t)
    mountDir := cipherDir + ".mnt"
    defer os.RemoveAll(cipherDir)
    defer os.RemoveAll(mountDir)

    test_helpers.MountOrFatal(t, cipherDir, mountDir, "-extpass", "echo test")
    defer test_helpers.UnmountPanic(mountDir)

    // Create two files with different content
    file1 := filepath.Join(mountDir, "file1.txt")
    file2 := filepath.Join(mountDir, "file2.txt")
    content1 := []byte("Content of file 1")
    content2 := []byte("Content of file 2")

    if err := os.WriteFile(file1, content1, 0644); err != nil {
        t.Fatalf("Failed to create file1: %v", err)
    }
    if err := os.WriteFile(file2, content2, 0644); err != nil {
        t.Fatalf("Failed to create file2: %v", err)
    }

    // Use RENAME_EXCHANGE to atomically swap the files
    err := syscallcompat.Renameat2(unix.AT_FDCWD, file1, unix.AT_FDCWD, file2, syscallcompat.RENAME_EXCHANGE)
    if err != nil {
        t.Fatalf("RENAME_EXCHANGE failed on gocryptfs: %v", err)
    }

    // Verify the files were swapped
    newContent1, err := os.ReadFile(file1)
    if err != nil {
        t.Fatalf("Failed to read file1 after exchange: %v", err)
    }
    newContent2, err := os.ReadFile(file2)
    if err != nil {
        t.Fatalf("Failed to read file2 after exchange: %v", err)
    }

    if string(newContent1) != string(content2) {
        t.Errorf("file1 content wrong after exchange. Expected: %s, Got: %s", content2, newContent1)
    }
    if string(newContent2) != string(content1) {
        t.Errorf("file2 content wrong after exchange. Expected: %s, Got: %s", content1, newContent2)
    }

    t.Logf("SUCCESS: RENAME_EXCHANGE works correctly on gocryptfs filesystem")
}

// TestMacOSAppSaveWorkflowOnGocryptfs tests the exact save workflow that
// macOS applications like Excel, Word, Numbers, and Pages use
func TestMacOSAppSaveWorkflowOnGocryptfs(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("This test is macOS-specific")
    }

    // Initialize and mount gocryptfs filesystem
    cipherDir := test_helpers.InitFS(t)
    mountDir := cipherDir + ".mnt"
    defer os.RemoveAll(cipherDir)
    defer os.RemoveAll(mountDir)

    test_helpers.MountOrFatal(t, cipherDir, mountDir, "-extpass", "echo test")
    defer test_helpers.UnmountPanic(mountDir)

    // Step 1: User opens an existing document
    documentPath := filepath.Join(mountDir, "MyDocument.xlsx")
    originalContent := []byte("Original Excel document content v1.0")
    if err := os.WriteFile(documentPath, originalContent, 0644); err != nil {
        t.Fatalf("Failed to create original document: %v", err)
    }

    // Step 2: User makes changes and saves - simulate the app save process
    for saveNumber := 1; saveNumber <= 3; saveNumber++ {
        t.Logf("Testing save #%d", saveNumber)
        
        // App creates a temp file with the new content
        tempPath := filepath.Join(mountDir, ".~MyDocument.xlsx.tmp")
        newContent := []byte("Updated Excel document content v" + string(rune('0'+saveNumber)) + ".0")
        
        if err := os.WriteFile(tempPath, newContent, 0644); err != nil {
            t.Fatalf("Save #%d: Failed to create temp file: %v", saveNumber, err)
        }

        // App atomically swaps the temp file with the original using RENAME_EXCHANGE
        // This is where the bug was in issue #914
        err := syscallcompat.Renameat2(unix.AT_FDCWD, tempPath, unix.AT_FDCWD, documentPath, syscallcompat.RENAME_EXCHANGE)
        if err != nil {
            t.Fatalf("Save #%d: Atomic save failed (this was the bug in issue #914): %v", saveNumber, err)
        }

        // App removes the temp file (which now contains the old content)
        if err := os.Remove(tempPath); err != nil {
            t.Fatalf("Save #%d: Failed to clean up temp file: %v", saveNumber, err)
        }

        // Verify the save worked
        savedContent, err := os.ReadFile(documentPath)
        if err != nil {
            t.Fatalf("Save #%d: Failed to read saved document: %v", saveNumber, err)
        }

        if string(savedContent) != string(newContent) {
            t.Errorf("Save #%d: Document not saved correctly. Expected: %s, Got: %s", 
                     saveNumber, newContent, savedContent)
        }

        t.Logf("Save #%d: SUCCESS", saveNumber)
    }

    t.Logf("All saves successful! Issue #914 is fixed - macOS apps can now save files on gocryptfs!")
}

// TestRenameExchangeWithSubdirectories tests RENAME_EXCHANGE in subdirectories
// as some apps create temp files in the same directory as the document
func TestRenameExchangeWithSubdirectories(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("This test is macOS-specific")
    }

    // Initialize and mount gocryptfs filesystem
    cipherDir := test_helpers.InitFS(t)
    mountDir := cipherDir + ".mnt"
    defer os.RemoveAll(cipherDir)
    defer os.RemoveAll(mountDir)

    test_helpers.MountOrFatal(t, cipherDir, mountDir, "-extpass", "echo test")
    defer test_helpers.UnmountPanic(mountDir)

    // Create a subdirectory for documents
    docDir := filepath.Join(mountDir, "Documents", "Projects")
    if err := os.MkdirAll(docDir, 0755); err != nil {
        t.Fatalf("Failed to create subdirectory: %v", err)
    }

    // Test RENAME_EXCHANGE in the subdirectory
    docFile := filepath.Join(docDir, "project.numbers")
    tempFile := filepath.Join(docDir, ".project.numbers.tmp")
    
    docContent := []byte("Numbers spreadsheet data")
    tempContent := []byte("Updated Numbers spreadsheet data")

    if err := os.WriteFile(docFile, docContent, 0644); err != nil {
        t.Fatalf("Failed to create document: %v", err)
    }
    if err := os.WriteFile(tempFile, tempContent, 0644); err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
    }

    // Perform the atomic exchange
    err := syscallcompat.Renameat2(unix.AT_FDCWD, tempFile, unix.AT_FDCWD, docFile, syscallcompat.RENAME_EXCHANGE)
    if err != nil {
        t.Fatalf("RENAME_EXCHANGE failed in subdirectory: %v", err)
    }

    // Verify the exchange worked
    savedContent, err := os.ReadFile(docFile)
    if err != nil {
        t.Fatalf("Failed to read saved document: %v", err)
    }

    if string(savedContent) != string(tempContent) {
        t.Errorf("Document not saved correctly. Expected: %s, Got: %s", tempContent, savedContent)
    }

    t.Logf("SUCCESS: RENAME_EXCHANGE works in subdirectories on gocryptfs")
}

// TestMacOSAppSaveSimulation simulates the behavior described in issue #914
// where macOS applications like Excel, Word, Numbers, and Pages fail to save files
func TestMacOSAppSaveSimulation(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("This test is macOS-specific")
    }

    // Initialize gocryptfs filesystem for testing
    cipherDir := test_helpers.InitFS(t)
    mountDir := cipherDir + ".mnt"
    defer os.RemoveAll(cipherDir)
    defer os.RemoveAll(mountDir)

    // Mount the gocryptfs filesystem
    test_helpers.MountOrFatal(t, cipherDir, mountDir, "-extpass", "echo test")
    defer test_helpers.UnmountPanic(mountDir)

    originalFile := filepath.Join(mountDir, "document.xlsx")
    originalContent := []byte("Original document content")

    if err := os.WriteFile(originalFile, originalContent, 0644); err != nil {
        t.Fatalf("Failed to create original document: %v", err)
    }

    for i := 0; i < 2; i++ {
        tempFile := filepath.Join(mountDir, ".~document.xlsx.tmp")
        updatedContent := []byte("Updated content version " + string(rune('1'+i)))

        if err := os.WriteFile(tempFile, updatedContent, 0644); err != nil {
            t.Fatalf("Failed to create temporary file for save: %v", err)
        }

        err := syscallcompat.Renameat2(unix.AT_FDCWD, tempFile, unix.AT_FDCWD, originalFile, syscallcompat.RENAME_EXCHANGE)
        if err != nil {
            t.Fatalf("Atomic save operation failed: %v", err)
        }

        savedContent, err := os.ReadFile(originalFile)
        if err != nil {
            t.Fatalf("Failed to read saved file: %v", err)
        }

        if string(savedContent) != string(updatedContent) {
            t.Errorf("Save operation didn't work correctly. Expected: %s, Got: %s", updatedContent, savedContent)
        }

        os.Remove(tempFile)
        t.Logf("Save iteration %d successful", i+1)
    }

    t.Logf("All iterative saves completed successfully")
}

// TestRenameat2_BasicFunctionality tests the Renameat2 function directly on native filesystem
func TestRenameat2_BasicFunctionality(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("This test is macOS-specific")
    }

    // Create a temporary directory for testing
    tmpDir, err := os.MkdirTemp("", "renameat2_test")
    if err != nil {
        t.Fatalf("Failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(tmpDir)

    // Test basic exchange functionality
    file1 := filepath.Join(tmpDir, "file1.txt")
    file2 := filepath.Join(tmpDir, "file2.txt")
    
    content1 := []byte("content of file 1")
    content2 := []byte("content of file 2")

    if err := os.WriteFile(file1, content1, 0644); err != nil {
        t.Fatalf("Failed to create file1: %v", err)
    }

    if err := os.WriteFile(file2, content2, 0644); err != nil {
        t.Fatalf("Failed to create file2: %v", err)
    }

    // Test RENAME_EXCHANGE - this is the core functionality for issue #914
    err = syscallcompat.Renameat2(unix.AT_FDCWD, file1, unix.AT_FDCWD, file2, syscallcompat.RENAME_EXCHANGE)
    if err != nil {
        t.Fatalf("RENAME_EXCHANGE failed: %v", err)
    }

    // Verify that the files have been swapped
    newContent1, err := os.ReadFile(file1)
    if err != nil {
        t.Fatalf("Failed to read file1 after exchange: %v", err)
    }

    newContent2, err := os.ReadFile(file2)
    if err != nil {
        t.Fatalf("Failed to read file2 after exchange: %v", err)
    }

    if string(newContent1) != string(content2) {
        t.Errorf("file1 content after exchange. Expected: %s, Got: %s", content2, newContent1)
    }

    if string(newContent2) != string(content1) {
        t.Errorf("file2 content after exchange. Expected: %s, Got: %s", content1, newContent2)
    }

    t.Logf("SUCCESS: RENAME_EXCHANGE worked correctly - files were swapped")
}

// TestMacOSAppSavePattern tests the specific pattern that macOS apps use on native filesystem
func TestMacOSAppSavePattern(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("This test is macOS-specific")
    }

    // Create a temporary directory for testing
    tmpDir, err := os.MkdirTemp("", "macos_save_test")
    if err != nil {
        t.Fatalf("Failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(tmpDir)

    // Simulate the macOS app save process:
    // 1. Original file exists
    // 2. App creates a temp file with new content
    // 3. App uses RENAME_EXCHANGE to atomically swap them
    
    originalFile := filepath.Join(tmpDir, "document.xlsx")
    tempFile := filepath.Join(tmpDir, ".~document.xlsx.tmp")
    
    originalContent := []byte("Original Excel document content")
    updatedContent := []byte("Updated Excel document content")

    // Step 1: Create original file (as if user opened an existing document)
    if err := os.WriteFile(originalFile, originalContent, 0644); err != nil {
        t.Fatalf("Failed to create original document: %v", err)
    }

    // Step 2: Create temp file with updated content (as app would do when saving)
    if err := os.WriteFile(tempFile, updatedContent, 0644); err != nil {
        t.Fatalf("Failed to create temp file: %v", err)
    }

    // Step 3: Atomic exchange (this is where the bug was in issue #914)
    err = syscallcompat.Renameat2(unix.AT_FDCWD, tempFile, unix.AT_FDCWD, originalFile, syscallcompat.RENAME_EXCHANGE)
    if err != nil {
        t.Fatalf("Atomic save operation failed (this was the bug in issue #914): %v", err)
    }

    // Verify the save worked
    savedContent, err := os.ReadFile(originalFile)
    if err != nil {
        t.Fatalf("Failed to read saved file: %v", err)
    }

    if string(savedContent) != string(updatedContent) {
        t.Errorf("Save operation didn't work correctly. Expected: %s, Got: %s", updatedContent, savedContent)
    }

    // The temp file should now contain the old content
    oldContent, err := os.ReadFile(tempFile)
    if err != nil {
        t.Fatalf("Failed to read temp file after exchange: %v", err)
    }

    if string(oldContent) != string(originalContent) {
        t.Errorf("Temp file doesn't contain old content. Expected: %s, Got: %s", originalContent, oldContent)
    }

    // Clean up temp file (as real apps would do)
    os.Remove(tempFile)

    t.Logf("SUCCESS: macOS app save pattern worked correctly")
    t.Logf("This confirms that issue #914 is fixed!")
}
