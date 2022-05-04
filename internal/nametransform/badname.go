package nametransform

import (
	"crypto/aes"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

const (
	// BadnameSuffix is appended to filenames in plaintext view if a corrupt
	// ciphername is shown due to a matching `-badname` pattern
	BadnameSuffix = " GOCRYPTFS_BAD_NAME"
)

// EncryptAndHashBadName tries to find the "name" substring, which (encrypted and hashed)
// leads to an unique existing file
// Returns ENOENT if cipher file does not exist or is not unique
func (be *NameTransform) EncryptAndHashBadName(name string, iv []byte, dirfd int) (cName string, err error) {
	var st unix.Stat_t
	var filesFound int
	lastFoundName, err := be.EncryptAndHashName(name, iv)
	if !strings.HasSuffix(name, BadnameSuffix) || err != nil {
		//Default mode: same behaviour on error or no BadNameFlag on "name"
		return lastFoundName, err
	}
	//Default mode: Check if File extists without modifications
	err = syscallcompat.Fstatat(dirfd, lastFoundName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		//file found, return result
		return lastFoundName, nil
	}
	//BadName Mode: check if the name was transformed without change (badname suffix and undecryptable cipher name)
	err = syscallcompat.Fstatat(dirfd, name[:len(name)-len(BadnameSuffix)], &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		filesFound++
		lastFoundName = name[:len(name)-len(BadnameSuffix)]
	}
	// search for the longest badname pattern match
	for charpos := len(name) - len(BadnameSuffix); charpos > 0; charpos-- {
		//only use original cipher name and append assumed suffix (without badname flag)
		cNamePart, err := be.EncryptName(name[:charpos], iv)
		if err != nil {
			//expand suffix on error
			continue
		}
		if len(cName) > be.longNameMax {
			cNamePart = be.HashLongName(cName)
		}
		cNameBadReverse := cNamePart + name[charpos:len(name)-len(BadnameSuffix)]
		err = syscallcompat.Fstatat(dirfd, cNameBadReverse, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			filesFound++
			lastFoundName = cNameBadReverse
		}
	}
	if filesFound == 1 {
		return lastFoundName, nil
	}
	// more than 1 possible file found, ignore
	return "", syscall.ENOENT
}

func (n *NameTransform) decryptBadname(cipherName string, iv []byte) (string, error) {
	for _, pattern := range n.badnamePatterns {
		match, err := filepath.Match(pattern, cipherName)
		// Pattern should have been validated already
		if err == nil && match {
			// Find longest decryptable substring
			// At least 16 bytes due to AES --> at least 22 characters in base64
			nameMin := n.B64.EncodedLen(aes.BlockSize)
			for charpos := len(cipherName) - 1; charpos >= nameMin; charpos-- {
				res, err := n.decryptName(cipherName[:charpos], iv)
				if err == nil {
					return res + cipherName[charpos:] + BadnameSuffix, nil
				}
			}
			return cipherName + BadnameSuffix, nil
		}
	}
	return "", syscall.EBADMSG
}

// HaveBadnamePatterns returns true if `-badname` patterns were provided
func (n *NameTransform) HaveBadnamePatterns() bool {
	return len(n.badnamePatterns) > 0
}
