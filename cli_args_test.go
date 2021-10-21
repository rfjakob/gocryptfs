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

	var testcases []testcaseContainer

	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs"},
		o: defaultArgs,
	})

	o := defaultArgs
	o.quiet = true
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "-q"},
		o: o,
	})
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "--q"},
		o: o,
	})
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "-quiet"},
		o: o,
	})
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "--quiet"},
		o: o,
	})

	o = defaultArgs
	o.exclude = []string{"foo", "bar"}
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "-e", "foo", "-e", "bar"},
		o: o,
	})
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "--exclude", "foo", "--exclude", "bar"},
		o: o,
	})
	/* TODO BROKEN
	testcases = append(testcases, testcaseContainer{
		i: []string{"gocryptfs", "--exclude", "foo", "-e", "bar"},
		o: o,
	})
	*/
	for _, tc := range testcases {
		o := parseCliOpts(tc.i)
		if !reflect.DeepEqual(o, tc.o) {
			t.Errorf("in=%v\nwant=%v\nhave=%v", tc.i, tc.o, o)
		}
	}
}
