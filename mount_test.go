package main

import "testing"

func TestDisableReadDirPlus(t *testing.T) {
	for _, tc := range []struct {
		name          string
		readdirplus   bool
		sharedstorage bool
		want          bool
	}{
		{name: "default", want: true},
		{name: "readdirplus", readdirplus: true},
		// -sharedstorage does not override an explicit -readdirplus.
		{name: "sharedstorage-default", sharedstorage: true, want: true},
		{name: "sharedstorage-readdirplus", readdirplus: true, sharedstorage: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &argContainer{
				readdirplus:   tc.readdirplus,
				sharedstorage: tc.sharedstorage,
			}
			got := baseMountOptions(args).DisableReadDirPlus
			if got != tc.want {
				t.Fatalf("DisableReadDirPlus=%v, want %v", got, tc.want)
			}
		})
	}
}
