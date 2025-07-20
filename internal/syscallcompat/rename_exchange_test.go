package syscallcompat

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRenameExchange(t *testing.T) {
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
	err = Renameat2(unix.AT_FDCWD, file1, unix.AT_FDCWD, file2, RENAME_EXCHANGE)
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
}
