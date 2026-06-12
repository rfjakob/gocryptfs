package main

import (
	"reflect"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
)

// TestPrefixOArgs checks that the "-o x,y,z" parsing works correctly.
func TestPrefixOArgs(t *testing.T) {
	testcases := []struct {
		// i is the input
		i []string
		// o is the expected output
		o []string
		// Do we expect an error?
		e bool
	}{
		{
			i: nil,
			o: nil,
		},
		{
			i: []string{"gocryptfs"},
			o: []string{"gocryptfs"},
		},
		{
			i: []string{"gocryptfs", "-v"},
			o: []string{"gocryptfs", "-v"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-v"},
			o: []string{"gocryptfs", "foo", "bar", "-v"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-o", "a"},
			o: []string{"gocryptfs", "-a", "foo", "bar"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-o", "a,b,xxxxx"},
			o: []string{"gocryptfs", "-a", "-b", "-xxxxx", "foo", "bar"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-d", "-o=a,b,xxxxx"},
			o: []string{"gocryptfs", "-a", "-b", "-xxxxx", "foo", "bar", "-d"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-oooo", "a,b,xxxxx"},
			o: []string{"gocryptfs", "foo", "bar", "-oooo", "a,b,xxxxx"},
		},
		// https://github.com/mhogomchungu/sirikali/blob/a36d91d3e39f0c1eb9a79680ed6c28ddb6568fa8/src/siritask.cpp#L192
		{
			i: []string{"gocryptfs", "-o", "rw", "--config", "fff", "ccc", "mmm"},
			o: []string{"gocryptfs", "-rw", "--config", "fff", "ccc", "mmm"},
		},
		// "--" should also block "-o" parsing.
		{
			i: []string{"gocryptfs", "foo", "bar", "--", "-o", "a"},
			o: []string{"gocryptfs", "foo", "bar", "--", "-o", "a"},
		},
		{
			i: []string{"gocryptfs", "--", "-o", "a"},
			o: []string{"gocryptfs", "--", "-o", "a"},
		},
		// This should error out
		{
			i: []string{"gocryptfs", "foo", "bar", "-o"},
			e: true,
		},
	}
	for _, tc := range testcases {
		o, err := prefixOArgs(tc.i)
		e := (err != nil)
		if !reflect.DeepEqual(o, tc.o) || e != tc.e {
			t.Errorf("\n  in=%q\nwant=%q err=%v\n got=%q err=%v", tc.i, tc.o, tc.e, o, e)
		}
	}
}

func TestConvertToDoubleDash(t *testing.T) {
	testcases := []struct {
		// i is the input
		i []string
		// o is the expected output
		o []string
	}{
		{
			i: nil,
			o: nil,
		},
		{
			i: []string{"gocryptfs"},
			o: []string{"gocryptfs"},
		},
		{
			i: []string{"gocryptfs", "foo"},
			o: []string{"gocryptfs", "foo"},
		},
		{
			i: []string{"gocryptfs", "-v", "-quiet"},
			o: []string{"gocryptfs", "--v", "--quiet"},
		},
		{
			i: []string{"gocryptfs", "--", "-foo"},
			o: []string{"gocryptfs", "--", "-foo"},
		},
	}
	for _, tc := range testcases {
		o := convertToDoubleDash(tc.i)
		if !reflect.DeepEqual(o, tc.o) {
			t.Errorf("in=%q\nwant=%q\nhave=%q", tc.i, tc.o, o)
		}
	}
}

func TestParseCliOpts(t *testing.T) {
	defaultArgs := argContainer{
		longnames:   true,
		longnamemax: 255,
		raw64:       true,
		hkdf:        true,
		openssl:     stupidgcm.PreferOpenSSLAES256GCM(), // depends on CPU and build flags
		scryptn:     16,
	}

	type testcaseContainer struct {
		// i is the input
		i []string
		// o is the expected output
		o argContainer
	}

	testcases := []testcaseContainer{
		{
			i: []string{"gocryptfs"},
			o: defaultArgs,
		},
	}

	o := defaultArgs
	o.quiet = true
	testcases = append(testcases, []testcaseContainer{
		{
			i: []string{"gocryptfs", "-q"},
			o: o,
		}, {
			i: []string{"gocryptfs", "--q"},
			o: o,
		}, {
			i: []string{"gocryptfs", "-quiet"},
			o: o,
		}, {
			i: []string{"gocryptfs", "--quiet"},
			o: o,
		},
	}...)

	o = defaultArgs
	o.exclude = []string{"foo", "bar", "baz,boe"}
	testcases = append(testcases, []testcaseContainer{
		{
			i: []string{"gocryptfs", "-e", "foo", "-e", "bar", "-e", "baz,boe"},
			o: o,
		}, {
			i: []string{"gocryptfs", "--exclude", "foo", "--exclude", "bar", "--exclude", "baz,boe"},
			o: o,
		}, /* TODO BROKEN {
			i: []string{"gocryptfs", "--exclude", "foo", "-e", "bar"},
			o: o,
		},*/
	}...)

	for _, tc := range testcases {
		o := parseCliOpts(tc.i)
		if !reflect.DeepEqual(o, tc.o) {
			t.Errorf("in=%v\nwant=%v\nhave=%v", tc.i, tc.o, o)
		}
	}
}

// TestMaybeExtractPostInitMountArgs checks the splitting of an all-in-one
// "-init ... -mount ..." command line.
func TestMaybeExtractPostInitMountArgs(t *testing.T) {
	testcases := []struct {
		// in is the input command line
		in []string
		// wantOsArgs is the expected (truncated) osArgs after the call
		wantOsArgs []string
		// wantMountArgs is the expected args._initAndMountArgsForMount
		wantMountArgs []string
		// wantPhase is the expected args._initAndMount
		wantPhase initMountPhase
		// wantErr is whether we expect an error
		wantErr bool
	}{
		// No "-mount": osArgs is left as is, nothing extracted.
		{
			in:         []string{"gocryptfs", "-init", "/tmp/cipher"},
			wantOsArgs: []string{"gocryptfs", "-init", "/tmp/cipher"},
			wantPhase:  phaseNone,
		},
		// Plain mount command line, no "-init" and no "-mount".
		{
			in:         []string{"gocryptfs", "/tmp/cipher", "/tmp/mnt"},
			wantOsArgs: []string{"gocryptfs", "/tmp/cipher", "/tmp/mnt"},
			wantPhase:  phaseNone,
		},
		// Valid split: everything after "-mount" goes to the mount list
		// (prefixed with the program name as the throwaway argv[0]), and
		// osArgs is truncated to everything before "-mount".
		{
			in:            []string{"gocryptfs", "-init", "/tmp/cipher", "-mount", "-q", "/tmp/cipher", "/tmp/mnt"},
			wantOsArgs:    []string{"gocryptfs", "-init", "/tmp/cipher"},
			wantMountArgs: []string{"gocryptfs", "-q", "/tmp/cipher", "/tmp/mnt"},
			wantPhase:     phaseInitWithMountQueued,
		},
		// Double-dash spelling: "--init" and "--mount" are recognized just
		// like their single-dash forms.
		{
			in:            []string{"gocryptfs", "--init", "/tmp/cipher", "--mount", "-q", "/tmp/cipher", "/tmp/mnt"},
			wantOsArgs:    []string{"gocryptfs", "--init", "/tmp/cipher"},
			wantMountArgs: []string{"gocryptfs", "-q", "/tmp/cipher", "/tmp/mnt"},
			wantPhase:     phaseInitWithMountQueued,
		},
		// A "--" terminator stops the scan: a "-mount" after it is treated as a
		// positional argument, not the phase separator, so nothing is extracted.
		{
			in:         []string{"gocryptfs", "-init", "--", "/tmp/cipher", "-mount", "/tmp/mnt"},
			wantOsArgs: []string{"gocryptfs", "-init", "--", "/tmp/cipher", "-mount", "/tmp/mnt"},
			wantPhase:  phaseNone,
		},
		// "-mount" without a preceding "-init" is an error.
		{
			in:      []string{"gocryptfs", "/tmp/cipher", "-mount", "-q", "/tmp/cipher", "/tmp/mnt"},
			wantErr: true,
		},
		// "-mount" with nothing following it is an error.
		{
			in:      []string{"gocryptfs", "-init", "/tmp/cipher", "-mount"},
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		osArgs := append([]string(nil), tc.in...)
		var args argContainer
		err := maybeExtractPostInitMountArgs(&osArgs, &args)
		if (err != nil) != tc.wantErr {
			t.Errorf("in=%q: wantErr=%v, got err=%v", tc.in, tc.wantErr, err)
			continue
		}
		if tc.wantErr {
			continue
		}
		if !reflect.DeepEqual(osArgs, tc.wantOsArgs) {
			t.Errorf("in=%q: osArgs\nwant=%q\n got=%q", tc.in, tc.wantOsArgs, osArgs)
		}
		if !reflect.DeepEqual(args._initAndMountArgsForMount, tc.wantMountArgs) {
			t.Errorf("in=%q: mountArgs\nwant=%q\n got=%q", tc.in, tc.wantMountArgs, args._initAndMountArgsForMount)
		}
		if args._initAndMount != tc.wantPhase {
			t.Errorf("in=%q: phase want=%d got=%d", tc.in, tc.wantPhase, args._initAndMount)
		}
	}
}

// TestInheritAuthentication checks the carry-over of the password and master
// key from the "-init" pass into the "-mount" pass.
func TestInheritAuthentication(t *testing.T) {
	// Not in phaseInitWithMountQueued: nothing is carried over or touched.
	t.Run("notQueued", func(t *testing.T) {
		prev := argContainer{
			_initAndMount: phaseNone,
			_password:     []byte("secret"),
			_masterkey:    []byte("mk"),
		}
		var args argContainer
		inheritAuthentication(&prev, &args)
		if args._initAndMount != phaseNone {
			t.Errorf("phase changed: got %d", args._initAndMount)
		}
		if args._password != nil || args._masterkey != nil {
			t.Errorf("secrets should not be carried over")
		}
	})

	// Password carry-over: no -passfile/-extpass on the mount side, so the
	// init password is transferred to args and cleared on prev.
	t.Run("passwordCarryover", func(t *testing.T) {
		pw := []byte("secret")
		prev := argContainer{
			_initAndMount: phaseInitWithMountQueued,
			_password:     pw,
		}
		var args argContainer
		inheritAuthentication(&prev, &args)
		if args._initAndMount != phaseMount {
			t.Errorf("phase want=%d got=%d", phaseMount, args._initAndMount)
		}
		if !reflect.DeepEqual(args._password, []byte("secret")) {
			t.Errorf("password not carried over: got %q", args._password)
		}
		if prev._password != nil {
			t.Errorf("prev._password should be nil after transfer")
		}
	})

	// User re-derives on the mount side (-extpass): init password must NOT be
	// carried over and must be wiped on prev.
	t.Run("passwordReDerive", func(t *testing.T) {
		pw := []byte("secret")
		prev := argContainer{
			_initAndMount: phaseInitWithMountQueued,
			_password:     pw,
		}
		args := argContainer{extpass: []string{"echo test"}}
		inheritAuthentication(&prev, &args)
		if args._password != nil {
			t.Errorf("password should not be carried over, got %q", args._password)
		}
		if prev._password != nil {
			t.Errorf("prev._password should be wiped (nil)")
		}
		for _, b := range pw {
			if b != 0 {
				t.Errorf("init password bytes should be zeroed, got %q", pw)
				break
			}
		}
	})

	// Master key carry-over: mount side uses -masterkey=init, so the init
	// master key is transferred and the sentinel string is cleared.
	t.Run("masterkeyCarryover", func(t *testing.T) {
		mk := []byte("mk")
		prev := argContainer{
			_initAndMount: phaseInitWithMountQueued,
			_masterkey:    mk,
		}
		args := argContainer{masterkey: "init"}
		inheritAuthentication(&prev, &args)
		if !reflect.DeepEqual(args._masterkey, []byte("mk")) {
			t.Errorf("masterkey not carried over: got %q", args._masterkey)
		}
		if prev._masterkey != nil {
			t.Errorf("prev._masterkey should be nil after transfer")
		}
		if args.masterkey != "" {
			t.Errorf("masterkey sentinel should be cleared, got %q", args.masterkey)
		}
	})

	// Master key not requested (no -masterkey=init): init master key must be
	// wiped on prev and not carried over.
	t.Run("masterkeyWiped", func(t *testing.T) {
		mk := []byte("mk")
		prev := argContainer{
			_initAndMount: phaseInitWithMountQueued,
			_masterkey:    mk,
		}
		var args argContainer
		inheritAuthentication(&prev, &args)
		if args._masterkey != nil {
			t.Errorf("masterkey should not be carried over, got %q", args._masterkey)
		}
		if prev._masterkey != nil {
			t.Errorf("prev._masterkey should be wiped (nil)")
		}
		for _, b := range mk {
			if b != 0 {
				t.Errorf("init masterkey bytes should be zeroed, got %q", mk)
				break
			}
		}
	})
}
