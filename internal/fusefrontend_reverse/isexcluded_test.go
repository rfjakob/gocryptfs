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
func TestShouldReturnFalseIfThereAreNoExclusions(t *testing.T) {
	var rfs ReverseFS
	if rfs.isExcluded("any/path") {
		t.Error("Should not exclude any path is no exclusions were specified")
	}
}

func TestShouldNoCallIgnoreParserForTranslatedConfig(t *testing.T) {
	ignorerMock := &IgnoreParserMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock

	if rfs.isExcluded(configfile.ConfDefaultName) {
		t.Error("Should not exclude translated config")
	}
	if ignorerMock.calledWith != "" {
		t.Error("Should not call IgnoreParser for translated config")
	}
}

func TestShouldNoCallIgnoreParserForDirIV(t *testing.T) {
	ignorerMock := &IgnoreParserMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock

	if rfs.isExcluded(nametransform.DirIVFilename) {
		t.Error("Should not exclude DirIV")
	}
	if ignorerMock.calledWith != "" {
		t.Error("Should not call IgnoreParser for DirIV")
	}
}
