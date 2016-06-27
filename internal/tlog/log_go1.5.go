// +build go1.5
// = go 1.5 or higher

package tlog

import (
	"log"
	"log/syslog"
)

func (l *toggledLogger) SwitchToSyslog(p syslog.Priority) {
	w, err := syslog.New(p, ProgramName)
	if err != nil {
		Warn.Printf("SwitchToSyslog: %v", err)
	} else {
		l.SetOutput(w)
	}
}

// SwitchLoggerToSyslog redirects the default log.Logger that the go-fuse lib uses
// to syslog.
func SwitchLoggerToSyslog(p syslog.Priority) {
	w, err := syslog.New(p, ProgramName)
	if err != nil {
		Warn.Printf("SwitchLoggerToSyslog: %v", err)
	} else {
		log.SetPrefix("go-fuse: ")
		// Disable printing the timestamp, syslog already provides that
		log.SetFlags(0)
		log.SetOutput(w)
	}
}
