package readpassword

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Provide password via stdin, terminated by "\n".
func TestStdin(t *testing.T) {
	p1 := "g55434t55wef"
	if os.Getenv("TEST_SLAVE") == "1" {
		p2 := string(readPasswordStdin("foo"))
		if p1 != p2 {
			fmt.Fprintf(os.Stderr, "%q != %q", p1, p2)
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStdin$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	n, err := pipe.Write([]byte(p1 + "\n"))
	if n == 0 || err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	if err != nil {
		t.Fatalf("slave failed with %v", err)
	}
}

// Provide password via stdin, terminated by EOF (pipe close). This should not
// hang.
func TestStdinEof(t *testing.T) {
	p1 := "asd45as5f4a36"
	if os.Getenv("TEST_SLAVE") == "1" {
		p2 := string(readPasswordStdin("foo"))
		if p1 != p2 {
			fmt.Fprintf(os.Stderr, "%q != %q", p1, p2)
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStdinEof$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	_, err = pipe.Write([]byte(p1))
	if err != nil {
		t.Fatal(err)
	}
	pipe.Close()
	err = cmd.Wait()
	if err != nil {
		t.Fatalf("slave failed with %v", err)
	}
}

// Provide empty password via stdin
func TestStdinEmpty(t *testing.T) {
	if os.Getenv("TEST_SLAVE") == "1" {
		readPasswordStdin("foo")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStdinEmpty$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	pipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	_, err = pipe.Write([]byte("\n"))
	if err != nil {
		t.Fatal(err)
	}
	pipe.Close()
	err = cmd.Wait()
	if err == nil {
		t.Fatalf("empty password should have failed")
	}
}
