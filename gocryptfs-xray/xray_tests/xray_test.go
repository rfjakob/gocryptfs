package xray_tests

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os/exec"
	"testing"
)

func TestAesgcmXray(t *testing.T) {
	expected, err := ioutil.ReadFile("aesgcm_fs.xray.txt")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("../gocryptfs-xray", "aesgcm_fs/fRtDWUFQK9vDAtAJrTbbWg")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(out, expected) != 0 {
		t.Errorf("Unexpected output")
		fmt.Printf("expected:\n%s", string(expected))
		fmt.Printf("have:\n%s", string(out))
	}
}

func TestAessivXray(t *testing.T) {
	expected, err := ioutil.ReadFile("aessiv_fs.xray.txt")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("../gocryptfs-xray", "-aessiv", "aessiv_fs/Ldq-c4ADpM5iGSSrPjUAqQ")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(out, expected) != 0 {
		t.Errorf("Unexpected output")
		fmt.Printf("expected:\n%s", string(expected))
		fmt.Printf("have:\n%s", string(out))
	}
}

func TestDumpmasterkey(t *testing.T) {
	expected := "f342380e238f708ff4eb94d1fcf79cca7e1e9d9ab91222865e4eaae8a292ee43\n"
	cmd := exec.Command("../gocryptfs-xray", "-dumpmasterkey", "aesgcm_fs/gocryptfs.conf")
	// Password = "test"
	cmd.Stdin = bytes.NewBuffer([]byte("test"))
	out1, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	out := string(out1)
	if out != expected {
		t.Errorf("Wrong output")
		fmt.Printf("expected: %s\n", expected)
		fmt.Printf("have: %s\n", out)
	}
}
