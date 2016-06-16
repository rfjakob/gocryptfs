package readpassword

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

func TestMain(m *testing.M) {
	// Shut up info output
	tlog.Info.Enabled = false
	os.Exit(m.Run())
}

func TestExtpass(t *testing.T) {
	p1 := "ads2q4tw41reg52"
	p2 := readPasswordExtpass("echo " + p1)
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

func TestOnceExtpass(t *testing.T) {
	p1 := "lkadsf0923rdfi48rqwhdsf"
	p2 := Once("echo " + p1)
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

func TestTwiceExtpass(t *testing.T) {
	p1 := "w5w44t3wfe45srz434"
	p2 := Once("echo " + p1)
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

// When extpass returns an empty string, we should crash.
// https://talks.golang.org/2014/testing.slide#23
func TestExtpassEmpty(t *testing.T) {
	if os.Getenv("TEST_SLAVE") == "1" {
		readPasswordExtpass("echo")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestExtpassEmpty$")
	cmd.Env = append(os.Environ(), "TEST_SLAVE=1")
	err := cmd.Run()
	if err != nil {
		return
	}
	t.Fatal("empty password should have failed")
}
