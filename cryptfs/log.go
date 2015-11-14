package cryptfs

import (
	"fmt"
	"strings"
)

type logChannel struct {
	enabled bool
}

func (l *logChannel) Printf(format string, args ...interface{}) {
	if l.enabled == true {
		fmt.Printf(format, args...)
	}
}

func (l *logChannel) Println(s string) {
	if l.enabled == true {
		fmt.Println(s)
	}
}

func (l *logChannel) Dump(d []byte) {
	s := string(d)
	fmt.Println(strings.Replace(s, "\000", "\\0", -1))
}

func (l *logChannel) Enable() {
	l.enabled = true
}

func (l *logChannel) Disable() {
	l.enabled = false
}

// Only actually calculate the md5sum if the log channel is enabled to save
// CPU cycles
func (l *logChannel) Md5sum(buf []byte) string {
	if l.enabled == false {
		return "disabled"
	}
	return md5sum(buf)
}

// As defined by http://elinux.org/Debugging_by_printing#Log_Levels

// Debug messages
var Debug = logChannel{false}

// Informational message e.g. startup information
var Info = logChannel{true}

// A warning, meaning nothing serious by itself but might indicate problems
var Warn = logChannel{true}
