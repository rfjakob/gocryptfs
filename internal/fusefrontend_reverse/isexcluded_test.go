package fusefrontend_reverse

import (
	"testing"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

type IgnoreParserMock struct {
	calledWith string
}

func (parser *IgnoreParserMock) MatchesPath(f string) bool {
	parser.calledWith = f
	return false
}

// Note: See also the integration tests in
// tests/reverse/exclude_test.go
func TestShouldNotCallIgnoreParserForTranslatedConfig(t *testing.T) {
	ignorerMock := &IgnoreParserMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock

	if excluded, _, _ := rfs.isExcludedCipher(configfile.ConfDefaultName); excluded {
		t.Error("Should not exclude translated config")
	}
	if ignorerMock.calledWith != "" {
		t.Error("Should not call IgnoreParser for translated config")
	}
}

func TestShouldNotCallIgnoreParserForDirIV(t *testing.T) {
	ignorerMock := &IgnoreParserMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock

	if excluded, _, _ := rfs.isExcludedCipher(nametransform.DirIVFilename); excluded {
		t.Error("Should not exclude DirIV")
	}
	if ignorerMock.calledWith != "" {
		t.Error("Should not call IgnoreParser for DirIV")
	}
}

func TestShouldReturnFalseIfThereAreNoExclusions(t *testing.T) {
	var rfs ReverseFS
	if rfs.isExcludedPlain("any/path") {
		t.Error("Should not exclude any path if no exclusions were specified")
	}
}

func TestShouldCallIgnoreParserToCheckExclusion(t *testing.T) {
	ignorerMock := &IgnoreParserMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock

	rfs.isExcludedPlain("some/path")
	if ignorerMock.calledWith != "some/path" {
		t.Error("Failed to call IgnoreParser")
	}

}
