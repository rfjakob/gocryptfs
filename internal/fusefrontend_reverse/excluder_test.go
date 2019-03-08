package fusefrontend_reverse

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

func TestShouldNoCreateExcluderIfNoPattersWereSpecified(t *testing.T) {
	var rfs ReverseFS
	var args fusefrontend.Args
	rfs.prepareExcluder(args)
	if rfs.excluder != nil {
		t.Error("Should not have created excluder")
	}
}

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

type IgnoreParserMock struct {
	toExclude  string
	calledWith string
}

func (parser *IgnoreParserMock) MatchesPath(f string) bool {
	parser.calledWith = f
	return f == parser.toExclude
}

type NameTransformMock struct {
	nametransform.NameTransform
}

func (n *NameTransformMock) DecryptName(cipherName string, iv []byte) (string, error) {
	return "mockdecrypt_" + cipherName, nil
}

// Note: See also the integration tests in
// tests/reverse/exclude_test.go
func TestShouldNotCallIgnoreParserForTranslatedConfig(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()

	if excluded, _, _ := rfs.isExcludedCipher(configfile.ConfDefaultName); excluded {
		t.Error("Should not exclude translated config")
	}
	if ignorerMock.calledWith != "" {
		t.Error("Should not call IgnoreParser for translated config")
	}
}

func TestShouldCheckIfParentIsExcludedForDirIV(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()
	path := "dir"
	ignorerMock.toExclude = "mockdecrypt_dir"
	dirIV := path + "/" + nametransform.DirIVFilename

	if excluded, _, _ := rfs.isExcludedCipher(dirIV); !excluded {
		t.Error("Should have excluded DirIV based on parent")
	}
	if ignorerMock.calledWith != "mockdecrypt_dir" {
		t.Errorf("Should have checked parent dir, checked %q", ignorerMock.calledWith)
	}
}

func TestShouldDecryptPathAndReturnTrueForExcludedPath(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()
	ignorerMock.toExclude = "mockdecrypt_file.txt"

	if excluded, _, _ := rfs.isExcludedCipher("file.txt"); !excluded {
		t.Error("Should have excluded")
	}
	if ignorerMock.calledWith != "mockdecrypt_file.txt" {
		t.Error("Didn't call IgnoreParser with decrypted path")
	}
}

func TestShouldReturnFalseIfThereAreNoExclusions(t *testing.T) {
	var rfs ReverseFS
	if rfs.isExcludedPlain("any/path") {
		t.Error("Should not exclude any path if no exclusions were specified")
	}
}

func TestShouldCallIgnoreParserToCheckExclusion(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()

	rfs.isExcludedPlain("some/path")
	if ignorerMock.calledWith != "some/path" {
		t.Error("Failed to call IgnoreParser")
	}
}

func createRFSWithMocks() (*ReverseFS, *IgnoreParserMock) {
	ignorerMock := &IgnoreParserMock{}
	nameTransformMock := &NameTransformMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock
	rfs.nameTransform = nameTransformMock
	return &rfs, ignorerMock
}
