// Package tlog is a "toggled logger" that can be enabled and disabled and
// provides coloring.
package tlog

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"os"

	"golang.org/x/term"
)

const (
	// ProgramName is used in log reports.
	ProgramName = "gocryptfs"
	wpanicMsg   = "-wpanic turns this warning into a panic: "
)

// Escape sequences for terminal colors. These are set in init() if and only
// if stdout is a terminal. Otherwise they are empty strings.
var (
	// ColorReset is used to reset terminal colors.
	ColorReset string
	// ColorGrey is a terminal color setting string.
	ColorGrey string
	// ColorRed is a terminal color setting string.
	ColorRed string
	// ColorGreen is a terminal color setting string.
	ColorGreen string
	// ColorYellow is a terminal color setting string.
	ColorYellow string
)

// JSONDump writes the object in json form.
func JSONDump(obj interface{}) string {
	b, err := json.MarshalIndent(obj, "", "\t")
	if err != nil {
		return err.Error()
	}

	return string(b)
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

	Logger *log.Logger
}

// trimNewline removes one trailing newline from "msg"
func trimNewline(msg string) string {
	if len(msg) == 0 {
		return msg
	}
	if msg[len(msg)-1] == '\n' {
		return msg[:len(msg)-1]
	}
	return msg
}

func (l *toggledLogger) Printf(format string, v ...interface{}) {
	if !l.Enabled {
		return
	}
	msg := trimNewline(fmt.Sprintf(format, v...))
	l.Logger.Printf(l.prefix + msg + l.postfix)
	if l.Wpanic {
		l.Logger.Panic(wpanicMsg + msg)
	}
}
func (l *toggledLogger) Println(v ...interface{}) {
	if !l.Enabled {
		return
	}
	msg := trimNewline(fmt.Sprint(v...))
	l.Logger.Println(l.prefix + msg + l.postfix)
	if l.Wpanic {
		l.Logger.Panic(wpanicMsg + msg)
	}
}

// Debug logs debug messages
// Can be enabled by passing "-d"
var Debug *toggledLogger

// Info logs informational message
// Can be disabled by passing "-q"
var Info *toggledLogger

// Warn logs warnings,
// meaning nothing serious by itself but might indicate problems.
// Passing "-wpanic" will make this function panic after printing the message.
var Warn *toggledLogger

// Fatal error, we are about to exit
var Fatal *toggledLogger

func init() {
	if term.IsTerminal(int(os.Stdout.Fd())) {
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
		prefix:  ColorYellow,
		postfix: ColorReset,
	}
	Fatal = &toggledLogger{
		Enabled: true,
		Logger:  log.New(os.Stderr, "", 0),
		prefix:  ColorRed,
		postfix: ColorReset,
	}
}

// SwitchToSyslog redirects the output of this logger to syslog.
// p = facility | severity
func (l *toggledLogger) SwitchToSyslog(p syslog.Priority) {
	w, err := syslog.New(p, ProgramName)
	if err != nil {
		Warn.Printf("SwitchToSyslog: %v", err)
	} else {
		l.Logger.SetOutput(w)
		// Disable colors
		l.prefix = ""
		l.postfix = ""
	}
}

// SwitchLoggerToSyslog redirects the default log.Logger that the go-fuse lib uses
// to syslog.
func SwitchLoggerToSyslog() {
	p := syslog.LOG_USER | syslog.LOG_WARNING
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

// PrintMasterkeyReminder reminds the user that he should store the master key in
// a safe place.
func PrintMasterkeyReminder(key []byte) {
	if !Info.Enabled {
		// Quiet mode
		return
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		// We don't want the master key to end up in a log file
		Info.Printf("Not running on a terminal, suppressing master key display\n")
		return
	}
	h := hex.EncodeToString(key)
	var hChunked string
	// Try to make it less scary by splitting it up in chunks
	for i := 0; i < len(h); i += 8 {
		hChunked += h[i : i+8]
		if i < 52 {
			hChunked += "-"
		}
		if i == 24 {
			hChunked += "\n    "
		}
	}
	Info.Printf(`
Your master key is:

    %s

If the gocryptfs.conf file becomes corrupted or you ever forget your password,
there is only one hope for recovery: The master key. Print it to a piece of
paper and store it in a drawer. This message is only printed once.

`, ColorGrey+hChunked+ColorReset)
}
