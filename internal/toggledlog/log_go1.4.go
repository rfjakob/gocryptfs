// +build !go1.5
// = go 1.4 or lower

package toggledlog

import (
	"log/syslog"
)

func (l *toggledLogger) SwitchToSyslog(p syslog.Priority) {
	Debug.Printf("Cannot switch to syslog - need Go 1.5 or higher")
}
