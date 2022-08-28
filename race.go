//go:build race
// +build race

package main

func init() {
	// adds " -race" to the output of "gocryptfs -version"
	raceDetector = true
}
