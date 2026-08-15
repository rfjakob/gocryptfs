package main

import "testing"

func TestDisableReadDirPlus(t *testing.T) {
	for _, tc := range []struct {
		name          string
		noreaddirplus bool
		sharedstorage bool
		want          bool
	}{
		{name: "default"},
		{name: "noreaddirplus", noreaddirplus: true, want: true},
		{name: "sharedstorage", sharedstorage: true, want: true},
		{name: "both", noreaddirplus: true, sharedstorage: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := &argContainer{
				noreaddirplus: tc.noreaddirplus,
				sharedstorage: tc.sharedstorage,
			}
			got := baseMountOptions(args).DisableReadDirPlus
			if got != tc.want {
				t.Fatalf("DisableReadDirPlus=%v, want %v", got, tc.want)
			}
		})
	}
}
