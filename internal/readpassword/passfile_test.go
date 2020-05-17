package readpassword

import (
	"os"
	"os/exec"
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
		pw := readPassFile("passfile_test_files/" + tc.file)
		if string(pw) != tc.want {
			t.Errorf("Wrong result: want=%q have=%q", tc.want, pw)
		}
		// Calling readPassFileConcatenate with only one element should give the
		// same result
		pw = readPassFileConcatenate([]string{"passfile_test_files/" + tc.file})
		if string(pw) != tc.want {
			t.Errorf("Wrong result: want=%q have=%q", tc.want, pw)
		}
	}
}

// readPassFile() should exit instead of returning an empty string.
//
// The TEST_SLAVE magic is explained at
// https://talks.golang.org/2014/testing.slide#23 , mirror:
// http://web.archive.org/web/20200426174352/https://talks.golang.org/2014/testing.slide#23
func TestPassfileEmpty(t *testing.T) {
	if os.Getenv("TEST_SLAVE") == "1" {
		readPassFile("passfile_test_files/empty.txt")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPassfileEmpty$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	err := cmd.Run()
	if err != nil {
		return
	}
	t.Fatal("should have exited")
}

// File containing just a newline.
// readPassFile() should exit instead of returning an empty string.
//
// The TEST_SLAVE magic is explained at
// https://talks.golang.org/2014/testing.slide#23 , mirror:
// http://web.archive.org/web/20200426174352/https://talks.golang.org/2014/testing.slide#23
func TestPassfileNewline(t *testing.T) {
	if os.Getenv("TEST_SLAVE") == "1" {
		readPassFile("passfile_test_files/newline.txt")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPassfileNewline$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	err := cmd.Run()
	if err != nil {
		return
	}
	t.Fatal("should have exited")
}

// File containing "\ngarbage".
// readPassFile() should exit instead of returning an empty string.
//
// The TEST_SLAVE magic is explained at
// https://talks.golang.org/2014/testing.slide#23 , mirror:
// http://web.archive.org/web/20200426174352/https://talks.golang.org/2014/testing.slide#23
func TestPassfileEmptyFirstLine(t *testing.T) {
	if os.Getenv("TEST_SLAVE") == "1" {
		readPassFile("passfile_test_files/empty_first_line.txt")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPassfileEmptyFirstLine$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	err := cmd.Run()
	if err != nil {
		return
	}
	t.Fatal("should have exited")
}

// TestPassFileConcatenate tests readPassFileConcatenate
func TestPassFileConcatenate(t *testing.T) {
	files := []string{
		"passfile_test_files/file with spaces.txt",
		"passfile_test_files/mypassword_garbage.txt",
	}
	res := string(readPassFileConcatenate(files))
	if res != "mypasswordmypassword" {
		t.Errorf("wrong result: %q", res)
	}
}
