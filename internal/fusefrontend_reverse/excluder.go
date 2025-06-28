package fusefrontend_reverse

import (
	"log"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"

	gitignore "github.com/rfjakob/gocryptfs/v2/internal/go-git-gitignore"
)

// prepareExcluder creates an object to check if paths are excluded
// based on the patterns specified in the command line.
func prepareExcluder(args fusefrontend.Args) gitignore.Matcher {
	lines := getExclusionPatterns(args)
	if len(lines) == 0 {
		log.Panic(lines)
	}

	var patterns []gitignore.Pattern
	for _, l := range lines {
		patterns = append(patterns, gitignore.ParsePattern(l, nil))
	}

	return gitignore.NewMatcher(patterns)
}

// getExclusionPatters prepares a list of patterns to be excluded.
// Patterns passed in the -exclude command line option are prefixed
// with a leading '/' to preserve backwards compatibility (before
// wildcard matching was implemented, exclusions always were matched
// against the full path).
func getExclusionPatterns(args fusefrontend.Args) []string {
	patterns := make([]string, len(args.Exclude)+len(args.ExcludeWildcard))
	// add -exclude
	for i, p := range args.Exclude {
		patterns[i] = "/" + p
	}
	// add -exclude-wildcard
	copy(patterns[len(args.Exclude):], args.ExcludeWildcard)
	// add -exclude-from
	for _, file := range args.ExcludeFrom {
		lines, err := getLines(file)
		if err != nil {
			tlog.Fatal.Printf("Error reading exclusion patterns: %q", err)
			os.Exit(exitcodes.ExcludeError)
		}
		patterns = append(patterns, lines...)
	}
	return patterns
}

// getLines reads a file and splits it into lines
func getLines(file string) ([]string, error) {
	buffer, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(buffer), "\n"), nil
}
