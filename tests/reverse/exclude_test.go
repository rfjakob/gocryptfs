package reverse_test

import (
	"log"
	"os"
	"path/filepath"
	"strings"
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

// doTestExcludeTestFs runs exclude tests against the exclude_test_fs folder.
// flag is either "--exclude-wildcard" or "--exclude"
func doTestExcludeTestFs(t *testing.T, flag string, patterns []string, tree directoryTree) {
	var extraArgs []string
	for _, v := range patterns {
		extraArgs = append(extraArgs, flag, v)
	}
	// Mount reverse fs
	backingDir, mnt, sock := newReverseFS(extraArgs)
	defer test_helpers.UnmountPanic(mnt)

	tree.createOnDisk(backingDir)

	// Get encrypted version of visible and hidden paths
	cVisible := encryptExcludeTestPaths(t, sock, tree.visible())
	cHidden := encryptExcludeTestPaths(t, sock, tree.hidden())

	// Check that hidden paths are not there and visible paths are there
	for _, v := range cHidden {
		if test_helpers.VerifyExistence(t, mnt+"/"+v) {
			t.Errorf("File %q is visible, but should be hidden", v)
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

type directoryTree struct {
	visibleFiles []string
	visibleDirs  []string
	hiddenFiles  []string
	hiddenDirs   []string
}

func (tr *directoryTree) visible() []string {
	return append(tr.visibleDirs, tr.visibleFiles...)
}

func (tr *directoryTree) hidden() []string {
	return append(tr.hiddenDirs, tr.hiddenFiles...)
}

func (tr *directoryTree) createOnDisk(baseDir string) {
	dirs := append(tr.hiddenDirs, tr.visibleDirs...)
	for _, d := range dirs {
		err := os.MkdirAll(baseDir+"/"+d, 0700)
		if err != nil {
			log.Panic(err)
		}
	}

	files := append(tr.hiddenFiles, tr.visibleFiles...)
	for _, f := range files {
		d := filepath.Dir(f)
		err := os.MkdirAll(baseDir+"/"+d, 0700)
		if err != nil {
			log.Panic(err)
		}
		err = os.WriteFile(baseDir+"/"+f, nil, 0600)
		if err != nil {
			log.Panic(err)
		}
	}
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
	var tree directoryTree
	// visible are plaintext paths that should be visible in the encrypted view
	tree.visibleFiles = []string{
		"file2",
		"dir1/longfile1" + x240,
		"dir1/longfile3" + x240,
		"longdir1" + x240 + "/file1",
		"longdir2" + x240 + "/file",
		"longfile1" + x240,
		"file3",
	}
	tree.visibleDirs = []string{
		"longdir1" + x240,
	}
	// hidden are plaintext paths that should be hidden in the encrypted view
	tree.hiddenFiles = []string{
		"bkp1~",
		"dir1/file1",
		"dir1/file2",
		"dir1/exclude",
		"dir1/longbkp1" + x240 + "~",
		"dir1/longfile2" + x240,
		"dir1/subdir1/exclude",
		"dir1/subdir1/subdir2/exclude",
		"dir2/file",
		"dir2/longdir1" + x240 + "/file",
		"dir2/longfile." + x240,
		"dir2/subdir/file",
		"file1",
		"longdir2" + x240 + "/bkp~",
		"longfile2" + x240,
		"longfile3" + x240,
	}
	tree.hiddenDirs = []string{
		"dir2",
		"dir2/subdir",
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, tree)
	doTestExcludeTestFs(t, "-ew", patterns, tree)
}

// Exclude everything using "/*", then selectively include only dir1 using "!/dir1"
// https://github.com/rfjakob/gocryptfs/issues/588
func TestExcludeAllOnlyDir1(t *testing.T) {
	// --exclude-wildcard patterns, gitignore syntax
	patterns := []string{
		"*",
		"!/dir1",
	}
	var tree directoryTree
	// visible are plaintext paths that should be visible in the encrypted view
	tree.visibleDirs = []string{
		"dir1",
	}
	tree.visibleFiles = []string{
		"dir1/file1",
	}
	// hidden are plaintext paths that should be hidden in the encrypted view
	tree.hiddenDirs = []string{
		"dir2",
		"dir2/subdir",
	}
	tree.hiddenFiles = []string{
		"dir2/file",
		"dir2/longdir1" + x240 + "/file",
		"dir2/longfile." + x240,
		"dir2/subdir/file",
		"file1",
		"longdir2" + x240 + "/bkp~",
		"longfile2" + x240,
		"longfile3" + x240,
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, tree)
}

// Test that the "exclude everything except" example
// from https://git-scm.com/docs/gitignore works
// (copied below):
//
//	$ cat .gitignore
//	# exclude everything except directory foo/bar
//	/*
//	!/foo
//	/foo/*
//	!/foo/bar
func TestGitignoreExampleExcludeEverythingExcept(t *testing.T) {
	// --exclude-wildcard patterns, gitignore syntax
	patterns := []string{
		"/*",
		"!/foo",
		"/foo/*",
		"!/foo/bar",
	}
	var tree directoryTree
	// visible are plaintext paths that should be visible in the encrypted view
	tree.visibleDirs = []string{
		"foo",
		"foo/bar",
	}
	tree.visibleFiles = []string{}
	// hidden are plaintext paths that should be hidden in the encrypted view
	tree.hiddenDirs = []string{
		"baz",
	}
	tree.hiddenFiles = []string{
		"boing",
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, tree)
}

// Issue https://github.com/rfjakob/gocryptfs/issues/927
//
// Patterns ending with "/" are not handled correctly by
// https://github.com/sabhiram/go-gitignore
func TestIssue927(t *testing.T) {
	patterns := strings.Split(`
/*
.gitignore
.config/**
!.config/
.config/conky/*
!.config/conky/
!.config/conky/conkyrc

.config/geany/*
!.config/geany/
.config/geany/colorschemes/*
!.config/geany/colorschemes/
!.config/geany/colorschemes/dark3.conf

/.config/mpv/*
!/.config/mpv/
!/.config/mpv/config
!/.config/mpv/scripts/
!/.config/mpv/scripts/*
.config/mpv/scripts/sub.lua
!/.config/mpv/script-opts/
!/.config/mpv/script-opts/*
!/.config/mpv/input.conf
`, "\n")
	var tree directoryTree
	// visible are plaintext paths that should be visible in the encrypted view
	tree.visibleDirs = []string{
		".config",
		".config/conky",
	}
	tree.visibleFiles = []string{
		".config/conky/conkyrc",
		".config/geany/colorschemes/dark3.conf",
		".config/mpv/input.conf",
		".config/mpv/script-opts/hello",
	}
	// hidden are plaintext paths that should be hidden in the encrypted view
	tree.hiddenDirs = []string{
		"ddd",
		".config/conky/ddd",
	}
	tree.hiddenFiles = []string{
		"fff",
		".config/conky/xxx",
		".config/geany/colorschemes/fff",
		".config/mpv/fff",
		".config/mpv/scripts/sub.lua",
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, tree)
}

// Subset of TestIssue927 to repro the "!dir/" issue
// https://github.com/go-git/go-git/issues/1596
func TestIssue927MinimalNotDir(t *testing.T) {
	patterns := strings.Split(`dir/*
!dir/`, "\n")
	var tree directoryTree
	// visible are plaintext paths that should be visible in the encrypted view
	tree.visibleDirs = []string{
		"dir",
	}
	tree.visibleFiles = []string{}
	// hidden are plaintext paths that should be hidden in the encrypted view
	tree.hiddenDirs = []string{}
	tree.hiddenFiles = []string{
		"dir/zzz",
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, tree)
}

func TestIssue927MinimalNotDir2(t *testing.T) {
	patterns := strings.Split(`.config/conky/*
!.config/conky/
!.config/conky/conkyrc`, "\n")
	var tree directoryTree
	// visible are plaintext paths that should be visible in the encrypted view
	tree.visibleDirs = []string{}
	tree.visibleFiles = []string{
		".config/conky/conkyrc",
	}
	// hidden are plaintext paths that should be hidden in the encrypted view
	tree.hiddenDirs = []string{}
	tree.hiddenFiles = []string{
		".config/conky/xxx",
	}
	doTestExcludeTestFs(t, "-exclude-wildcard", patterns, tree)
}
