package ctlsocksrv

import (
	"testing"
)

func TestSanitizePath(t *testing.T) {
	testCases := [][]string{
		{"", ""},
		{".", ""},
		{"/", ""},
		{"foo", "foo"},
		{"/foo", "foo"},
		{"foo/", "foo"},
		{"/foo/", "foo"},
		{"/foo/./foo", "foo/foo"},
		{"./", ""},
		{"..", ""},
		{"foo/../..", ""},
		{"foo/../../aaaaaa", ""},
		{"/foo/../../aaaaaa", ""},
		{"/////", ""},
	}
	for _, tc := range testCases {
		res := SanitizePath(tc[0])
		if res != tc[1] {
			t.Errorf("%q: got %q, want %q", tc[0], res, tc[1])
		}
	}
}
