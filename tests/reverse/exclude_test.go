package reverse_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func ctlsockEncryptPath(t *testing.T, sock string, path string) string {
	req := ctlsock.RequestStruct{EncryptPath: path}
	response := test_helpers.QueryCtlSock(t, sock, req)
	if response.ErrNo != 0 {
		t.Fatal(response)
	}
	return response.Result
}

// doTestExcludeTestFs runs exclude tests against the exclude_test_fs folder
func doTestExcludeTestFs(t *testing.T, flag string, patterns, visible, hidden []string) {
	// Mount reverse fs
	mnt, err := ioutil.TempDir(test_helpers.TmpDir, t.Name())
	if err != nil {
		t.Fatal(err)
	}
	sock := mnt + ".sock"
	cliArgs := []string{"-reverse", "-extpass", "echo test", "-ctlsock", sock}
	for _, v := range patterns {
		cliArgs = append(cliArgs, flag, v)
	}
	if plaintextnames {
		cliArgs = append(cliArgs, "-config", "exclude_test_fs/.gocryptfs.reverse.conf.plaintextnames")
	}
	test_helpers.MountOrFatal(t, "exclude_test_fs", mnt, cliArgs...)
	defer test_helpers.UnmountPanic(mnt)

	// Get encrypted version of visible and hidden paths
	cVisible := encryptExcludeTestPaths(t, sock, visible)
	cHidden := encryptExcludeTestPaths(t, sock, hidden)

	// Check that hidden paths are not there and visible paths are there
	for _, v := range cHidden {
		if test_helpers.VerifyExistence(t, mnt+"/"+v) {
			t.Errorf("File %q is visible, but should be hidden", v)
		}
		if nametransform.IsLongContent(filepath.Base(v)) {
			// TODO ???
		}
	}
	for _, v := range cVisible {
		if !test_helpers.VerifyExistence(t, mnt+"/"+v) {
			t.Errorf("File %q is hidden, but should be visible", v)
		}
	}
}

// encryptExcludeTestPaths is used by doTestExcludeTestFs() to encrypt the lists of
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

// TestExcludeTestFs runs exclude tests against the exclude_test_fs folder.
func TestExcludeTestFs(t *testing.T) {
	// --exclude-wildcard patterns, gitignore syntax
	patterns := []string{
		"file1",                       // matches file1 anywhere
		"!longdir1" + x240 + "/file1", // ! includes an otherwise file
		"file2/",                      // a trailing slash matches only a directory
		"dir1/file2",                  // matches file2 inside dir1 anywhere
		"#file2",                      // comments are ignored
		"dir2",                        // excludes the whole directory
		"longfile2" + x240,            // matches longfile2 anywhere
		"/longfile3" + x240,           // a leading / anchors the match at the root
		"*~",                          // wildcards are supported
		"dir1/**/exclude",             // ** matches any number of directories
		"file3/",                      // pattern with trailing slash should not match a file
	}
	// visible are plaintext paths that should be visible in the encrypted view
	visible := []string{
		"file2",
		"dir1/longfile1" + x240,
		"dir1/longfile3" + x240,
		"longdir1" + x240,
		"longdir1" + x240 + "/file1",
		"longdir2" + x240 + "/file",
		"longfile1" + x240,
		"file3",
	}
	// hidden are plaintext paths that should be hidden in the encrypted view
	hidden := []string{
		"bkp1~",
		"dir1/file1",
		"dir1/file2",
		"dir1/exclude",
		"dir1/longbkp1" + x240 + "~",
		"dir1/longfile2" + x240,
		"dir1/subdir1/exclude",
		"dir1/subdir1/subdir2/exclude",
		"dir2",
		"dir2/file",
		"dir2/longdir1" + x240 + "/file",
		"dir2/longfile." + x240,
		"dir2/subdir",
		"dir2/subdir/file",
		"file1",
		"longdir2" + x240 + "/bkp~",
		"longfile2" + x240,
		"longfile3" + x240,
	}

	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, visible, hidden)
	doTestExcludeTestFs(t, "-ew", patterns, visible, hidden)
}

// Exclude everything using "/*", then selectively include only dir1 using "!/dir1"
// https://github.com/rfjakob/gocryptfs/issues/588
func TestExcludeAllOnlyDir1(t *testing.T) {
	// --exclude-wildcard patterns, gitignore syntax
	patterns := []string{
		"*",
		"!/dir1",
	}
	// visible are plaintext paths that should be visible in the encrypted view
	visible := []string{
		"dir1",
		"dir1/file1",
	}
	// hidden are plaintext paths that should be hidden in the encrypted view
	hidden := []string{
		"dir2",
		"dir2/file",
		"dir2/longdir1" + x240 + "/file",
		"dir2/longfile." + x240,
		"dir2/subdir",
		"dir2/subdir/file",
		"file1",
		"longdir2" + x240 + "/bkp~",
		"longfile2" + x240,
		"longfile3" + x240,
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, visible, hidden)
}
