package tlog

import (
	"testing"
)

// Test that trimNewline() works as expected
func TestTrimNewline(t *testing.T) {
	testTable := []struct {
		in   string
		want string
	}{
		{"...\n", "..."},
		{"\n...\n", "\n..."},
		{"", ""},
		{"\n", ""},
		{"\n\n", "\n"},
		{"   ", "   "},
	}
	for _, v := range testTable {
		have := trimNewline(v.in)
		if v.want != have {
			t.Errorf("want=%q have=%q", v.want, have)
		}
	}
}
