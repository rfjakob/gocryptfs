package reverse_test

import (
	"io/ioutil"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var ctlSockTestCases = [][]string{
	{"4RQq1dJlfvQPaVU5Xypf0w==", "file"},
	{"gocryptfs.longname.ZQCAoi5li3xvDZRO8McBV0L_kzJc4IcAOEzuW-2S1Y4=", "longfile." + x240},
	{"v6puXntoQOk7Mhl8zJ4Idg==", "dir"},
	{"v6puXntoQOk7Mhl8zJ4Idg==/UVy2gV0RQTUC8AE4wYoMwg==", "dir/file"},
	{"v6puXntoQOk7Mhl8zJ4Idg==/fvHFLHlxHCQ7EpVMJu0AZg==", "dir/dir"},
	{"v6puXntoQOk7Mhl8zJ4Idg==/fvHFLHlxHCQ7EpVMJu0AZg==/_4uudIGniACke55JoDsqDA==", "dir/dir/dir"},
	{"v6puXntoQOk7Mhl8zJ4Idg==/fvHFLHlxHCQ7EpVMJu0AZg==/QvPahkkeVRKTw2kdZFZxwQ==", "dir/dir/file"},
	{"v6puXntoQOk7Mhl8zJ4Idg==/gocryptfs.longname.y6rxCn6Id8hIZL2t_STpdLZpu-aE2HpprJR25xD60mk=", "dir/longfile." + x240},
	{"gocryptfs.longname.cvRximo1ATRJVEzw_V9MZieHFlod9y2iv2Sug1kbiTE=", "longdir." + x240},
	{"gocryptfs.longname.cvRximo1ATRJVEzw_V9MZieHFlod9y2iv2Sug1kbiTE=/-LMdFgFt6UxO-z5iJvuC9w==", "longdir." + x240 + "/dir"},
	{"gocryptfs.longname.cvRximo1ATRJVEzw_V9MZieHFlod9y2iv2Sug1kbiTE=/rBPJYAzcHWLdPj1T8kgh8A==", "longdir." + x240 + "/file"},
}

// Test DecryptPath and EncryptPath
func TestCtlSockPathOps(t *testing.T) {
	if plaintextnames {
		t.Skip("this only tests encrypted names")
	}
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, "reverse_mnt_")
	if err != nil {
		t.Fatal(err)
	}
	sock := mnt + ".sock"
	test_helpers.MountOrFatal(t, "ctlsock_reverse_test_fs", mnt, "-reverse", "-extpass", "echo test", "-ctlsock="+sock)
	defer test_helpers.UnmountPanic(mnt)
	var req ctlsock.RequestStruct
	var response ctlsock.ResponseStruct
	for i, tc := range ctlSockTestCases {
		// Decrypt
		req = ctlsock.RequestStruct{DecryptPath: tc[0]}
		response = test_helpers.QueryCtlSock(t, sock, req)
		if response.ErrNo != 0 {
			t.Errorf("Testcase %d Decrypt: %q ErrNo=%d ErrText=%s", i, tc[0], response.ErrNo, response.ErrText)
		} else if response.Result != tc[1] {
			t.Errorf("Testcase %d Decrypt: Want %q got %q", i, tc[1], response.Result)
		}
		// Encrypt
		req = ctlsock.RequestStruct{EncryptPath: tc[1]}
		response = test_helpers.QueryCtlSock(t, sock, req)
		if response.ErrNo != 0 {
			t.Errorf("Testcase %d Encrypt: %q ErrNo=%d ErrText=%s", i, tc[0], response.ErrNo, response.ErrText)
		} else if response.Result != tc[0] {
			t.Errorf("Testcase %d Encrypt: Want %q got %q", i, tc[1], response.Result)
		}
	}
	// At this point the longname parent cache should be populated.
	// Check that we do not mix up information for different directories.
	req = ctlsock.RequestStruct{DecryptPath: "gocryptfs.longname.y6rxCn6Id8hIZL2t_STpdLZpu-aE2HpprJR25xD60mk="}
	response = test_helpers.QueryCtlSock(t, sock, req)
	if response.ErrNo != int32(syscall.ENOENT) {
		t.Errorf("File should not exist: ErrNo=%d ErrText=%s", response.ErrNo, response.ErrText)
	}
	req = ctlsock.RequestStruct{DecryptPath: "v6puXntoQOk7Mhl8zJ4Idg==/gocryptfs.longname.ZQCAoi5li3xvDZRO8McBV0L_kzJc4IcAOEzuW-2S1Y4="}
	response = test_helpers.QueryCtlSock(t, sock, req)
	if response.ErrNo != int32(syscall.ENOENT) {
		t.Errorf("File should not exist: ErrNo=%d ErrText=%s", response.ErrNo, response.ErrText)
	}
}

// We should not panic when somebody feeds requests that make no sense
func TestCtlSockCrash(t *testing.T) {
	if plaintextnames {
		t.Skip("this only tests encrypted names")
	}
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, "reverse_mnt_")
	if err != nil {
		t.Fatal(err)
	}
	sock := mnt + ".sock"
	test_helpers.MountOrFatal(t, "ctlsock_reverse_test_fs", mnt, "-reverse", "-extpass", "echo test", "-ctlsock="+sock,
		"-wpanic=0", "-nosyslog=0")
	defer test_helpers.UnmountPanic(mnt)
	// Try to crash it
	req := ctlsock.RequestStruct{DecryptPath: "gocryptfs.longname.XXX_TestCtlSockCrash_XXX.name"}
	test_helpers.QueryCtlSock(t, sock, req)
}
