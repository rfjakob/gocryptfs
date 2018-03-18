package fusefrontend

// This file is named "xattr_unit_test.go" because there is also a
// "xattr_integration_test.go" in the test/xattr package.

import (
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

func newTestFS() *FS {
	// Init crypto backend
	key := make([]byte, cryptocore.KeyLen)
	cCore := cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, true, false)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS, false)
	nameTransform := nametransform.New(cCore.EMECipher, true, true)
	args := Args{}
	return NewFS(args, cEnc, nameTransform)
}

func TestEncryptDecryptXattrName(t *testing.T) {
	fs := newTestFS()
	_, err := fs.encryptXattrName("xxxx")
	if err != syscall.EPERM {
		t.Fatalf("Names that don't start with 'user.' should fail")
	}
	attr1 := "user.foo123456789"
	cAttr, err := fs.encryptXattrName(attr1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cAttr=%v", cAttr)
	attr2, err := fs.decryptXattrName(cAttr)
	if attr1 != attr2 {
		t.Fatalf("Decrypt mismatch: %v != %v", attr1, attr2)
	}
}
