package toggledlog

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

const (
	ProgramName = "gocryptfs"
	wpanicMsg   = "-wpanic turns this warning into a panic: "
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
	// Enable or disable output
	Enabled bool
	// Panic after logging a message, useful in regression tests
	Wpanic bool
	*log.Logger
}

func (l *toggledLogger) Printf(format string, v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Printf(format, v...)
	if l.Wpanic {
		l.Logger.Panic(wpanicMsg + fmt.Sprintf(format, v...))
	}
}
func (l *toggledLogger) Println(v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Println(v...)
	if l.Wpanic {
		l.Logger.Panic(wpanicMsg + fmt.Sprintln(v...))
	}
}

// Debug messages
// Can be enabled by passing "-d"
var Debug *toggledLogger

// Informational message
// Can be disabled by passing "-q"
var Info *toggledLogger

// A warning, meaning nothing serious by itself but might indicate problems.
// Passing "-wpanic" will make this function panic after printing the message.
var Warn *toggledLogger

// Fatal error, we are about to exit
var Fatal *toggledLogger

func init() {
	Debug = &toggledLogger{false, false, log.New(os.Stdout, "", 0)}
	Info = &toggledLogger{true, false, log.New(os.Stdout, "", 0)}
	Warn = &toggledLogger{true, false, log.New(os.Stderr, "", 0)}
	Fatal = &toggledLogger{true, false, log.New(os.Stderr, "", 0)}
}
