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

	ftype, excluded, _, err := rfs.getFileInfo(configfile.ConfDefaultName)
	if err != nil {
		t.Errorf("Unexpected error %q\n", err)
	}
	if ftype != config {
		t.Errorf("Wrong file type, expecting %d, got %d\n", config, ftype)
	}
	if excluded {
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

	ftype, excluded, _, err := rfs.getFileInfo(dirIV)
	if err != nil {
		t.Errorf("Unexpected error %q\n", err)
	}
	if ftype != diriv {
		t.Errorf("Wrong file type, expecting %d, got %d\n", diriv, ftype)
	}
	if !excluded {
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

	ftype, excluded, _, err := rfs.getFileInfo(dirIV)
	if err != nil {
		t.Errorf("Unexpected error %q\n", err)
	}
	if ftype != namefile {
		t.Errorf("Wrong file type, expecting %d, got %d\n", namefile, ftype)
	}
	if !excluded {
		t.Error("Should have excluded LongName based on parent")
	}
	if ignorerMock.calledWith != "mockdecrypt_parent" {
		t.Errorf("Should have checked parent dir, checked %q", ignorerMock.calledWith)
	}
}

func TestShouldDecryptPathAndReturnTrueForExcludedPath(t *testing.T) {
	rfs, ignorerMock := createRFSWithMocks()
	ignorerMock.toExclude = "mockdecrypt_file.txt"

	ftype, excluded, pPath, err := rfs.getFileInfo("file.txt")
	if err != nil {
		t.Errorf("Unexpected error %q\n", err)
	}
	if ftype != regular {
		t.Errorf("Wrong file type, expecting %d, got %d\n", regular, ftype)
	}
	if !excluded {
		t.Error("Should have excluded")
	}
	if pPath != "mockdecrypt_file.txt" {
		t.Errorf("Wrong pPath returned, got %q\n", pPath)
	}
	if ignorerMock.calledWith != "mockdecrypt_file.txt" {
		t.Error("Didn't call IgnoreParser with decrypted path")
	}
}
