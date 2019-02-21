package fusefrontend_reverse

import (
	"os"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"

	"github.com/sabhiram/go-gitignore"
)

// prepareExcluder creates an object to check if paths are excluded
// based on the patterns specified in the command line.
func (rfs *ReverseFS) prepareExcluder(args fusefrontend.Args) {
	if len(args.Exclude) > 0 {
		excluder, err := ignore.CompileIgnoreLines(args.Exclude...)
		if err != nil {
			tlog.Fatal.Printf("Error compiling exclusion rules: %q", err)
			os.Exit(exitcodes.ExcludeError)
		}
		rfs.excluder = excluder
	}
}

// isExcludedCipher finds out if relative ciphertext path "relPath" is
// excluded (used when -exclude is passed by the user).
// If relPath is not a special file, it returns the decrypted path or error
// from decryptPath for convenience.
func (rfs *ReverseFS) isExcludedCipher(relPath string) (bool, string, error) {
	if rfs.isTranslatedConfig(relPath) || rfs.isDirIV(relPath) {
		return false, "", nil
	}
	if rfs.isNameFile(relPath) {
		relPath = nametransform.RemoveLongNameSuffix(relPath)
	}
	decPath, err := rfs.decryptPath(relPath)
	excluded := err == nil && rfs.isExcludedPlain(decPath)
	return excluded, decPath, err
}

// isExcludedPlain finds out if the plaintext path "pPath" is
// excluded (used when -exclude is passed by the user).
func (rfs *ReverseFS) isExcludedPlain(pPath string) bool {
	return rfs.excluder != nil && rfs.excluder.MatchesPath(pPath)
}
