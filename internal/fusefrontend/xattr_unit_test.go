package fusefrontend

// This file is named "xattr_unit_test.go" because there is also a
// "xattr_integration_test.go" in the test/xattr package.

import (
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

func newTestFS(args Args) *RootNode {
	// Init crypto backend
	key := make([]byte, cryptocore.KeyLen)
	cCore := cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, true)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS)
	n := nametransform.New(cCore.EMECipher, true, 0, true, nil, false)
	rn := NewRootNode(args, cEnc, n)
	oneSec := time.Second
	options := &fs.Options{
		EntryTimeout: &oneSec,
		AttrTimeout:  &oneSec,
	}
	fs.NewNodeFS(rn, options)
	return rn
}

func TestEncryptDecryptXattrName(t *testing.T) {
	fs := newTestFS(Args{})
	attr1 := "user.foo123456789"
	cAttr, err := fs.encryptXattrName(attr1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cAttr=%v", cAttr)
	attr2, err := fs.decryptXattrName(cAttr)
	if attr1 != attr2 || err != nil {
		t.Fatalf("Decrypt mismatch: %v != %v", attr1, attr2)
	}
}
