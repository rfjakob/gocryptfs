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
