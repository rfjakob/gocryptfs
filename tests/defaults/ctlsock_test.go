package defaults

import (
	"os"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestCtlSock(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)
	req := ctlsock.RequestStruct{
		EncryptPath: "foobar",
	}
	response := test_helpers.QueryCtlSock(t, sock, req)
	if response.Result == "" || response.ErrNo != 0 {
		t.Errorf("got an error reply: %+v", response)
	}
	req.EncryptPath = "not-existing-dir/xyz"
	response = test_helpers.QueryCtlSock(t, sock, req)
	if response.ErrNo != int32(syscall.ENOENT) || response.Result != "" {
		t.Errorf("incorrect error handling: wanted ErrNo=%d, have %+v", syscall.ENOENT, response)
	}
	// Strange paths should not cause a crash
	crashers := []string{"/foo", "foo/", "/foo/", ".", "/////", "/../../."}
	for _, c := range crashers {
		req.EncryptPath = c
		// QueryCtlSock calls t.Fatal if it gets EOF when gocryptfs panics
		response = test_helpers.QueryCtlSock(t, sock, req)
		if response.WarnText == "" {
			t.Errorf("We should get a warning about non-canonical paths here")
		}
	}
}

func TestCtlSockDecrypt(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)

	paths := []string{
		"xxxxxxx123456789",
		"foo/bar/baz",
		test_helpers.X255,
		"123/" + test_helpers.X255,
		"123/" + test_helpers.X255 + "/456",
	}

	for _, p := range paths {
		// Create path
		err := os.MkdirAll(pDir+"/"+p, 0700)
		if err != nil {
			t.Fatal(err)
		}
		// Encrypt the path through the ctlsock
		req := ctlsock.RequestStruct{
			EncryptPath: p,
		}
		response := test_helpers.QueryCtlSock(t, sock, req)
		if response.Result == "" || response.ErrNo != 0 {
			t.Fatalf("got an error for query %+v: %+v", req, response)
		}
		// Check if the encrypted path actually exists
		cPath := response.Result
		_, err = os.Stat(cDir + "/" + cPath)
		if err != nil {
			t.Fatal(err)
		}
		// Decrypt the path through the ctlsock and see if we get the original path
		req = ctlsock.RequestStruct{
			DecryptPath: cPath,
		}
		response = test_helpers.QueryCtlSock(t, sock, req)
		if response.Result == "" || response.ErrNo != 0 {
			t.Errorf("query=%+v, response=%+v", req, response)
			continue
		}
		if response.Result != p {
			t.Errorf("want=%q got=%q", p, response.Result)
		}
	}
}

func TestCtlSockDecryptCrash(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(pDir)
}
