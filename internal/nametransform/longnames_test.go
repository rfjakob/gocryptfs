package nametransform

import (
	"testing"
)

func TestIsLongName(t *testing.T) {
	n := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU=.name"
	if IsLongName(n) != 2 {
		t.Errorf("False negative")
	}

	n = "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if IsLongName(n) != 1 {
		t.Errorf("False negative")
	}

	n = "LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if IsLongName(n) != 0 {
		t.Errorf("False positive")
	}
}
