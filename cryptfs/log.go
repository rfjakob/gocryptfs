package cryptfs

import (
	"encoding/json"
	"log"
	"log/syslog"
	"os"
)

func JSONDump(obj interface{}) string {
	b, err := json.MarshalIndent(obj, "", "\t")
	if err != nil {
		return err.Error()
	} else {
		return string(b)
	}
}

// toggledLogger - a Logger than can be enabled and disabled
type toggledLogger struct {
	Enabled bool
	*log.Logger
}

func (l *toggledLogger) Printf(format string, v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Printf(format, v...)
}
func (l *toggledLogger) Println(v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Println(v...)
}
func (l *toggledLogger) SwitchToSyslog(p syslog.Priority) {
	w, err := syslog.New(p, PROGRAM_NAME)
	if err != nil {
		Warn.Printf("Cannot switch 0x%02x to syslog: %v", p, err)
	} else {
		l.SetOutput(w)
	}
}

// As defined by http://elinux.org/Debugging_by_printing#Log_Levels
// Debug messages
var Debug *toggledLogger

// Informational message e.g. startup information
var Info *toggledLogger

// A warning, meaning nothing serious by itself but might indicate problems
var Warn *toggledLogger

func init() {
	Debug = &toggledLogger{false, log.New(os.Stdout, "", 0)}
	Info = &toggledLogger{true, log.New(os.Stdout, "", 0)}
	Warn = &toggledLogger{true, log.New(os.Stderr, "", 0)}
}
