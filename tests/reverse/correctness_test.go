package reverse_test

import (
	"os"
	"testing"
	//"time"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

func TestLongnameStat(t *testing.T) {
	fd, err := os.Create(dirA + "/" + x240)
	if err != nil {
		t.Fatal(err)
	}
	path := dirC + "/" + x240
	if !test_helpers.VerifyExistence(path) {
		t.Fail()
	}
	test_helpers.VerifySize(t, path, 0)
	_, err = fd.Write(make([]byte, 10))
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	/*
		time.Sleep(1000 * time.Millisecond)
		test_helpers.VerifySize(t, path, 10)
	*/
}
