// Package tlog is a "toggled logger" that can be enabled and disabled and
// provides coloring.
package tlog

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	ProgramName = "gocryptfs"
	wpanicMsg   = "-wpanic turns this warning into a panic: "
)

// Escape sequences for terminal colors. These will be empty strings if stdout
// is not a terminal.
var ColorReset, ColorGrey, ColorRed, ColorGreen, ColorYellow string

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
	// Private prefix and postfix are used for coloring
	prefix  string
	postfix string

	*log.Logger
}

func (l *toggledLogger) Printf(format string, v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Printf(l.prefix + fmt.Sprintf(format, v...) + l.postfix)
	if l.Wpanic {
		l.Logger.Panic(wpanicMsg + fmt.Sprintf(format, v...))
	}
}
func (l *toggledLogger) Println(v ...interface{}) {
	if !l.Enabled {
		return
	}
	l.Logger.Println(l.prefix + fmt.Sprint(v...) + l.postfix)
	if l.Wpanic {
		l.Logger.Panic(wpanicMsg + fmt.Sprint(v...))
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
	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		ColorReset = "\033[0m"
		ColorGrey = "\033[2m"
		ColorRed = "\033[31m"
		ColorGreen = "\033[32m"
		ColorYellow = "\033[33m"
	}

	Debug = &toggledLogger{
		Logger: log.New(os.Stdout, "", 0),
	}
	Info = &toggledLogger{
		Enabled: true,
		Logger:  log.New(os.Stdout, "", 0),
	}
	Warn = &toggledLogger{
		Enabled: true,
		Logger:  log.New(os.Stderr, "", 0),
	}
	Fatal = &toggledLogger{
		Enabled: true,
		Logger:  log.New(os.Stderr, "", 0),
		prefix:  ColorRed,
		postfix: ColorReset,
	}
}
