package main

import (
	"reflect"
	"testing"
)

// TestFlagTokenIndex checks the raw command-line flag finder.
func TestFlagTokenIndex(t *testing.T) {
	args := []string{"gocryptfs", "-init", "/cipher", "-q", "-mount", "/plain", "-fg"}
	testcases := []struct {
		names []string
		want  int
	}{
		{names: []string{"-init", "--init"}, want: 1},
		{names: []string{"-mount", "--mount"}, want: 4},
		{names: []string{"-q", "--q"}, want: 3},
		{names: []string{"-fg", "--fg"}, want: 6},
		{names: []string{"-nonexistent"}, want: -1},
	}
	for _, tc := range testcases {
		if got := flagTokenIndex(args, tc.names...); got != tc.want {
			t.Errorf("flagTokenIndex(%v): want=%d, got=%d", tc.names, tc.want, got)
		}
	}
}

// TestFlagTokenIndexStopsAtDoubleDash verifies that "--" disables detection.
func TestFlagTokenIndexStopsAtDoubleDash(t *testing.T) {
	args := []string{"gocryptfs", "--", "-mount", "/plain"}
	if got := flagTokenIndex(args, "-mount", "--mount"); got != -1 {
		t.Errorf("expected -1 after \"--\", got %d", got)
	}
}

// TestDetectInitMount checks detection of the combined init+mount mode.
func TestDetectInitMount(t *testing.T) {
	testcases := []struct {
		name     string
		args     []string
		wantOK   bool
		wantInit int
		wantMnt  int
	}{
		{
			name:     "combined init and mount",
			args:     []string{"gocryptfs", "-init", "/cipher", "-mount", "/plain"},
			wantOK:   true,
			wantInit: 1,
			wantMnt:  3,
		},
		{
			name:   "only init",
			args:   []string{"gocryptfs", "-init", "/cipher"},
			wantOK: false,
		},
		{
			name:   "only mount",
			args:   []string{"gocryptfs", "-mount", "/plain"},
			wantOK: false,
		},
		{
			name:   "plain mount, neither flag",
			args:   []string{"gocryptfs", "/cipher", "/plain"},
			wantOK: false,
		},
		{
			name:     "double dash spelling",
			args:     []string{"gocryptfs", "--init", "/cipher", "--mount", "/plain"},
			wantOK:   true,
			wantInit: 1,
			wantMnt:  3,
		},
		{
			name:     "mount before init (still detected, order checked later)",
			args:     []string{"gocryptfs", "-mount", "/plain", "-init", "/cipher"},
			wantOK:   true,
			wantInit: 3,
			wantMnt:  1,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pos, ok := detectInitMount(tc.args)
			if ok != tc.wantOK {
				t.Fatalf("ok: want=%v got=%v", tc.wantOK, ok)
			}
			if ok {
				if pos.initPos != tc.wantInit || pos.mountPos != tc.wantMnt {
					t.Errorf("positions: want init=%d mount=%d, got init=%d mount=%d",
						tc.wantInit, tc.wantMnt, pos.initPos, pos.mountPos)
				}
			}
		})
	}
}

// TestInitMountArgSplitting verifies the two argument sets are built exactly as
// described: init = [prog] + (-init .. before -mount); mount = [prog, cipherdir]
// + (everything after -mount).
func TestInitMountArgSplitting(t *testing.T) {
	osArgs := []string{"gocryptfs", "-init", "-q", "/cipher", "-mount", "/plain", "-fg", "-allow_other"}
	pos, ok := detectInitMount(osArgs)
	if !ok {
		t.Fatal("expected combined mode to be detected")
	}

	initArgs := append([]string{osArgs[0]}, osArgs[pos.initPos:pos.mountPos]...)
	wantInit := []string{"gocryptfs", "-init", "-q", "/cipher"}
	if !reflect.DeepEqual(initArgs, wantInit) {
		t.Errorf("initArgs: want=%v got=%v", wantInit, initArgs)
	}

	cipherdir := "/cipher"
	mountArgs := append([]string{osArgs[0], cipherdir}, osArgs[pos.mountPos+1:]...)
	wantMount := []string{"gocryptfs", "/cipher", "/plain", "-fg", "-allow_other"}
	if !reflect.DeepEqual(mountArgs, wantMount) {
		t.Errorf("mountArgs: want=%v got=%v", wantMount, mountArgs)
	}
}
