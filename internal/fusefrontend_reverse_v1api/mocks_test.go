package fusefrontend_reverse

import (
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

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

func createRFSWithMocks() (*ReverseFS, *IgnoreParserMock) {
	ignorerMock := &IgnoreParserMock{}
	nameTransformMock := &NameTransformMock{}
	var rfs ReverseFS
	rfs.excluder = ignorerMock
	rfs.nameTransform = nameTransformMock
	return &rfs, ignorerMock
}
