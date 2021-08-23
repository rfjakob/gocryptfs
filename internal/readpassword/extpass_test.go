package readpassword

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func TestMain(m *testing.M) {
	// Shut up info output
	tlog.Info.Enabled = false
	os.Exit(m.Run())
}

func TestExtpass(t *testing.T) {
	p1 := "ads2q4tw41reg52"
	p2 := string(readPasswordExtpass([]string{"echo " + p1}))
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

func TestOnceExtpass(t *testing.T) {
	p1 := "lkadsf0923rdfi48rqwhdsf"
	p2 := string(Once([]string{"echo " + p1}, nil, ""))
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

// extpass with two arguments
func TestOnceExtpass2(t *testing.T) {
	p1 := "foo"
	p2 := string(Once([]string{"echo", p1}, nil, ""))
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

// extpass with three arguments
func TestOnceExtpass3(t *testing.T) {
	p1 := "foo bar baz"
	p2 := string(Once([]string{"echo", "foo", "bar", "baz"}, nil, ""))
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

func TestOnceExtpassSpaces(t *testing.T) {
	p1 := "mypassword"
	p2 := string(Once([]string{"cat", "passfile_test_files/file with spaces.txt"}, nil, ""))
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

func TestTwiceExtpass(t *testing.T) {
	p1 := "w5w44t3wfe45srz434"
	p2 := string(Once([]string{"echo " + p1}, nil, ""))
	if p1 != p2 {
		t.Errorf("p1=%q != p2=%q", p1, p2)
	}
}

// When extpass returns an empty string, we should crash.
//
// The TEST_SLAVE magic is explained at
// https://talks.golang.org/2014/testing.slide#23 .
func TestExtpassEmpty(t *testing.T) {
	if os.Getenv("TEST_SLAVE") == "1" {
		readPasswordExtpass([]string{"echo"})
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
