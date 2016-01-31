package cryptfs

import (
	"encoding/json"
	"fmt"
	"log"
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
	// Enable or disable output
	Enabled bool
	// Panic after logging a message, useful in regression tests
	PanicAfter bool
	*log.Logger
}

func (l *toggledLogger) Printf(format string, v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Printf(format, v...)
	if l.PanicAfter {
		panic("PanicAfter: " + fmt.Sprintf(format, v...))
	}
}
func (l *toggledLogger) Println(v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Println(v...)
	if l.PanicAfter {
		panic("PanicAfter: " + fmt.Sprintln(v...))
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
	Debug = &toggledLogger{false, false, log.New(os.Stdout, "", 0)}
	Info = &toggledLogger{true, false, log.New(os.Stdout, "", 0)}
	Warn = &toggledLogger{true, false, log.New(os.Stderr, "", 0)}
}
