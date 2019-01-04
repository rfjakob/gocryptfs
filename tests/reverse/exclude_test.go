package reverse_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/tests/test_helpers"
)

const xxx = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

/*
tree exclude_test_fs
exclude_test_fs/
├── dir1
│   ├── file1
│   ├── file2
│   ├── longfile1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   └── longfile2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
├── dir2
│   ├── file
│   ├── longdir1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   │   └── file
│   ├── longfile.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   └── subdir
│       └── file
├── file1
├── file2
├── longdir1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   └── file
├── longdir2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   └── file
├── longfile1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
└── longfile2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
*/

func ctlsockEncryptPath(t *testing.T, sock string, path string) string {
	req := ctlsock.RequestStruct{EncryptPath: path}
	response := test_helpers.QueryCtlSock(t, sock, req)
	if response.ErrNo != 0 {
		t.Fatal(response)
	}
	return response.Result
}

func testExclude(t *testing.T, flag string) {
	pOk := []string{
		"file2",
		"dir1/file1",
		"dir1/longfile1" + xxx,
		"longdir1" + xxx,
		"longdir1" + xxx + "/file",
		"longfile1" + xxx,
	}
	pExclude := []string{
		"file1",
		"dir1/file2",
		"dir1/longfile2" + xxx,
		"dir2",
		"dir2/file",
		"dir2/file/xxx",
		"dir2/subdir",
		"dir2/subdir/file",
		"dir2/longdir1" + xxx + "/file",
		"dir2/longfile." + xxx,
		"longfile2" + xxx,
	}
	// Mount reverse fs
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, "TestExclude")
	if err != nil {
		t.Fatal(err)
	}
	sock := mnt + ".sock"
	cliArgs := []string{"-reverse", "-extpass", "echo test", "-ctlsock", sock}
	for _, v := range pExclude {
		cliArgs = append(cliArgs, flag, v)
	}
	if plaintextnames {
		cliArgs = append(cliArgs, "-config", "exclude_test_fs/.gocryptfs.reverse.conf.plaintextnames")
	}
	test_helpers.MountOrFatal(t, "exclude_test_fs", mnt, cliArgs...)
	defer test_helpers.UnmountPanic(mnt)
	// Get encrypted version of "ok" and "excluded" paths
	cOk := encryptExcludeTestPaths(t, sock, pOk)
	cExclude := encryptExcludeTestPaths(t, sock, pExclude)
	// Check that "excluded" paths are not there and "ok" paths are there
	for _, v := range cExclude {
		if test_helpers.VerifyExistence(mnt + "/" + v) {
			t.Errorf("File %q is visible, but should be excluded", v)
		}
		if nametransform.IsLongContent(filepath.Base(v)) {

		}
	}
	for _, v := range cOk {
		if !test_helpers.VerifyExistence(mnt + "/" + v) {
			t.Errorf("File %q is hidden, but should be visible", v)
		}
	}
}

// encryptExcludeTestPaths is used by testExclude() to encrypt the lists of
// testcase paths
func encryptExcludeTestPaths(t *testing.T, socket string, pRelPaths []string) (out []string) {
	for _, pRelPath := range pRelPaths {
		cRelPath := ctlsockEncryptPath(t, socket, pRelPath)
		out = append(out, cRelPath)
		if !plaintextnames && nametransform.IsLongContent(filepath.Base(cRelPath)) {
			// If we exclude
			//   gocryptfs.longname.3vZ_r3eDPb1_fL3j5VA4rd_bcKWLKT9eaxOVIGK5HFA
			// we should also exclude
			//   gocryptfs.longname.3vZ_r3eDPb1_fL3j5VA4rd_bcKWLKT9eaxOVIGK5HFA.name
			out = append(out, cRelPath+nametransform.LongNameSuffix)
		}
	}
	return out
}

func TestExclude(t *testing.T) {
	testExclude(t, "-exclude")
	testExclude(t, "-e")
}
