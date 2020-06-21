package fusefrontend

import (
	"time"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// reportMitigatedCorruption is used to report a corruption that was transparently
// mitigated and did not return an error to the user. Pass the name of the corrupt
// item (filename for OpenDir(), xattr name for ListXAttr() etc).
// See the MitigatedCorruptions channel for more info.
func (rn *RootNode) reportMitigatedCorruption(item string) {
	if rn.MitigatedCorruptions == nil {
		return
	}
	select {
	case rn.MitigatedCorruptions <- item:
	case <-time.After(1 * time.Second):
		tlog.Warn.Printf("BUG: reportCorruptItem: timeout")
		//debug.PrintStack()
		return
	}
}
