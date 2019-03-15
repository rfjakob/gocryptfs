package fusefrontend_reverse

import (
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

func TestShouldDetectDirIV(t *testing.T) {
	var rfs ReverseFS
	ftype := rfs.getFileType("some/path/" + nametransform.DirIVFilename)
	if ftype != diriv {
		t.Errorf("Expecting %d, got %d\n", diriv, ftype)
	}
}

func TestShouldDetectNameFile(t *testing.T) {
	var rfs ReverseFS
	ftype := rfs.getFileType("dir1/dir2/gocryptfs.longname.URrM8kgxTKYMgCk4hKk7RO9Lcfr30XQof4L_5bD9Iro=" + nametransform.LongNameSuffix)
	if ftype != namefile {
		t.Errorf("Expecting %d, got %d\n", namefile, ftype)
	}
}

func TestShouldDetectConfigFile(t *testing.T) {
	var rfs ReverseFS
	ftype := rfs.getFileType(configfile.ConfDefaultName)
	if ftype != config {
		t.Errorf("Expecting %d, got %d\n", config, ftype)
	}
}

func TestShouldDetectRegularFile(t *testing.T) {
	var rfs ReverseFS
	ftype := rfs.getFileType("documents/text_file.txt")
	if ftype != regular {
		t.Errorf("Expecting %d, got %d\n", regular, ftype)
	}
}

// Note: For path exclusion, see also the integration tests in
// tests/reverse/exclude_test.go
func TestShouldNotCallIgnoreParserForTranslatedConfig(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()

	if excluded, _, _ := rfs.getFileInfo(configfile.ConfDefaultName); excluded {
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

	if excluded, _, _ := rfs.getFileInfo(dirIV); !excluded {
		t.Error("Should have excluded DirIV based on parent")
	}
	if ignorerMock.calledWith != "mockdecrypt_dir" {
		t.Errorf("Should have checked parent dir, checked %q", ignorerMock.calledWith)
	}
}

func TestShouldCheckIfParentIsExcludedForLongName(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()
	path := "parent"
	ignorerMock.toExclude = "mockdecrypt_parent"
	dirIV := path + "/" + "gocryptfs.longname.fake.name"

	if excluded, _, _ := rfs.getFileInfo(dirIV); !excluded {
		t.Error("Should have excluded LongName based on parent")
	}
	if ignorerMock.calledWith != "mockdecrypt_parent" {
		t.Errorf("Should have checked parent dir, checked %q", ignorerMock.calledWith)
	}
}

func TestShouldDecryptPathAndReturnTrueForExcludedPath(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()
	ignorerMock.toExclude = "mockdecrypt_file.txt"

	if excluded, _, _ := rfs.getFileInfo("file.txt"); !excluded {
		t.Error("Should have excluded")
	}
	if ignorerMock.calledWith != "mockdecrypt_file.txt" {
		t.Error("Didn't call IgnoreParser with decrypted path")
	}
}
