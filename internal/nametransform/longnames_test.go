package nametransform

import (
	"testing"
)

func TestIsLongName(t *testing.T) {
	n := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU=.name"
	if NameType(n) != LongNameFilename {
		t.Errorf("False negative")
	}

	n = "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if NameType(n) != LongNameContent {
		t.Errorf("False negative")
	}

	n = "LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if NameType(n) != LongNameNone {
		t.Errorf("False positive")
	}
}

func TestRemoveLongNameSuffix(t *testing.T) {
	filename := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU=.name"
	content := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if RemoveLongNameSuffix(filename) != content {
		t.Error(".name suffix not removed")
	}
}
