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
