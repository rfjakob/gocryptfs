package reverse_test

import (
	"os"
	"testing"
)

func TestLongnameStat(t *testing.T) {
	_, err := os.Stat(dirA + "/" + "")
	if err != nil {
		t.Error(err)
	}
	_, err = os.Stat(dirA + "/" + "")
	if err != nil {
		t.Error(err)
	}
}
