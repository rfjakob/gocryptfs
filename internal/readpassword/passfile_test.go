package readpassword

import (
	"testing"
)

func TestPassfile(t *testing.T) {
	testcases := []struct {
		file string
		want string
	}{
		{"mypassword.txt", "mypassword"},
		{"mypassword_garbage.txt", "mypassword"},
		{"mypassword_missing_newline.txt", "mypassword"},
		{"file with spaces.txt", "mypassword"},
	}
	for _, tc := range testcases {
		pw, err := readPassFile("passfile_test_files/" + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		if string(pw) != tc.want {
			t.Errorf("Wrong result: want=%q have=%q", tc.want, pw)
		}
		// Calling readPassFileConcatenate with only one element should give the
		// same result
		pw, err = readPassFileConcatenate([]string{"passfile_test_files/" + tc.file})
		if err != nil {
			t.Fatal(err)
		}
		if string(pw) != tc.want {
			t.Errorf("Wrong result: want=%q have=%q", tc.want, pw)
		}
	}
}

// readPassFile() should fail instead of returning an empty string.
func TestPassfileEmpty(t *testing.T) {
	_, err := readPassFile("passfile_test_files/empty.txt")
	if err == nil {
		t.Fatal("should have failed")
	}
}

// File containing just a newline.
// readPassFile() should fal instead of returning an empty string.
func TestPassfileNewline(t *testing.T) {
	_, err := readPassFile("passfile_test_files/newline.txt")
	if err == nil {
		t.Fatal("should have failed")
	}
}

// File containing "\ngarbage".
// readPassFile() should return an error.
func TestPassfileEmptyFirstLine(t *testing.T) {
	_, err := readPassFile("passfile_test_files/empty_first_line.txt")
	if err == nil {
		t.Fatal("should have failed")
	}
}

// TestPassFileConcatenate tests readPassFileConcatenate
func TestPassFileConcatenate(t *testing.T) {
	files := []string{
		"passfile_test_files/file with spaces.txt",
		"passfile_test_files/mypassword_garbage.txt",
	}
	res, err := readPassFileConcatenate(files)
	if err != nil {
		t.Fatal(err)
	}
	if string(res) != "mypasswordmypassword" {
		t.Errorf("wrong result: %q", res)
	}
}
