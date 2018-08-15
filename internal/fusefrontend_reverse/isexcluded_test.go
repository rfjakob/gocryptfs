package fusefrontend_reverse

import (
	"testing"
)

func verifyExcluded(t *testing.T, rfs *ReverseFS, paths []string) {
	for _, p := range paths {
		if !rfs.isExcluded(p) {
			t.Errorf("Path %q should be excluded, but is not", p)
		}
	}
	if t.Failed() {
		t.Logf("cExclude = %#v", rfs.cExclude)
	}
}

// Note: See also the integration tests in
// tests/reverse/exclude_test.go
func TestIsExcluded(t *testing.T) {
	var rfs ReverseFS
	// If the root directory is excluded, all files and subdirs should be excluded
	// as well
	rfs.cExclude = []string{""}
	verifyExcluded(t, &rfs, []string{"", "foo", "foo/bar"})
}
