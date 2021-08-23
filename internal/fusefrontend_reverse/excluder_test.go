package fusefrontend_reverse

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
)

func TestShouldPrefixExcludeValuesWithSlash(t *testing.T) {
	var args fusefrontend.Args
	args.Exclude = []string{"file1", "dir1/file2.txt"}
	args.ExcludeWildcard = []string{"*~", "build/*.o"}

	expected := []string{"/file1", "/dir1/file2.txt", "*~", "build/*.o"}

	patterns := getExclusionPatterns(args)
	if !reflect.DeepEqual(patterns, expected) {
		t.Errorf("expected %q, got %q", expected, patterns)
	}
}

func TestShouldReadExcludePatternsFromFiles(t *testing.T) {
	tmpfile1, err := ioutil.TempFile("", "excludetest")
	if err != nil {
		t.Fatal(err)
	}
	exclude1 := tmpfile1.Name()
	defer os.Remove(exclude1)
	defer tmpfile1.Close()

	tmpfile2, err := ioutil.TempFile("", "excludetest")
	if err != nil {
		t.Fatal(err)
	}
	exclude2 := tmpfile2.Name()
	defer os.Remove(exclude2)
	defer tmpfile2.Close()

	tmpfile1.WriteString("file1.1\n")
	tmpfile1.WriteString("file1.2\n")
	tmpfile2.WriteString("file2.1\n")
	tmpfile2.WriteString("file2.2\n")

	var args fusefrontend.Args
	args.ExcludeWildcard = []string{"cmdline1"}
	args.ExcludeFrom = []string{exclude1, exclude2}

	// An empty string is returned for the last empty line
	// It's ignored when the patterns are actually compiled
	expected := []string{"cmdline1", "file1.1", "file1.2", "", "file2.1", "file2.2", ""}

	patterns := getExclusionPatterns(args)
	if !reflect.DeepEqual(patterns, expected) {
		t.Errorf("expected %q, got %q", expected, patterns)
	}
}

func TestShouldReturnFalseIfThereAreNoExclusions(t *testing.T) {
	var rfs RootNode
	if rfs.isExcludedPlain("any/path") {
		t.Error("Should not exclude any path if no exclusions were specified")
	}
}
