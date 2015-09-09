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

func (l *logChannel) Dump(d []byte) {
	s := string(d)
	fmt.Println(strings.Replace(s, "\000", "\\0", -1))
}

func (l *logChannel) Enable() {
	l.enabled = true
}


var Debug = logChannel{false}
var Warn = logChannel{true}
