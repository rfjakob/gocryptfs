package nametransform

import (
	"testing"
)

func TestIsLongName(t *testing.T) {
	n := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU=.name"
	if IsLongName(n) != LongNameFilename {
		t.Errorf("False negative")
	}

	n = "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if IsLongName(n) != LongNameContent {
		t.Errorf("False negative")
	}

	n = "LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if IsLongName(n) != LongNameNone {
		t.Errorf("False positive")
	}
}
