package readpassword

import (
	"os"
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
	p2, err := readPasswordExtpass([]string{"echo " + p1})
	if err != nil {
		t.Fatal(err)
	}
	if p1 != string(p2) {
		t.Errorf("p1=%q != p2=%q", p1, string(p2))
	}
}

func TestOnceExtpass(t *testing.T) {
	p1 := "lkadsf0923rdfi48rqwhdsf"
	p2, err := Once([]string{"echo " + p1}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != string(p2) {
		t.Errorf("p1=%q != p2=%q", p1, string(p2))
	}
}

// extpass with two arguments
func TestOnceExtpass2(t *testing.T) {
	p1 := "foo"
	p2, err := Once([]string{"echo", p1}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != string(p2) {
		t.Errorf("p1=%q != p2=%q", p1, string(p2))
	}
}

// extpass with three arguments
func TestOnceExtpass3(t *testing.T) {
	p1 := "foo bar baz"
	p2, err := Once([]string{"echo", "foo", "bar", "baz"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != string(p2) {
		t.Errorf("p1=%q != p2=%q", p1, string(p2))
	}
}

func TestOnceExtpassSpaces(t *testing.T) {
	p1 := "mypassword"
	p2, err := Once([]string{"cat", "passfile_test_files/file with spaces.txt"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != string(p2) {
		t.Errorf("p1=%q != p2=%q", p1, string(p2))
	}
}

func TestTwiceExtpass(t *testing.T) {
	p1 := "w5w44t3wfe45srz434"
	p2, err := Once([]string{"echo " + p1}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != string(p2) {
		t.Errorf("p1=%q != p2=%q", p1, string(p2))
	}
}

// Empty extpass should fail
func TestExtpassEmpty(t *testing.T) {
	_, err := readPasswordExtpass([]string{"echo"})
	if err == nil {
		t.Fatal("empty password should have failed")
	}
}
