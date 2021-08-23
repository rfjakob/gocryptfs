package main

import (
	"os"
	"runtime/pprof"
	"runtime/trace"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// setupCpuprofile is called to handle a non-empty "-cpuprofile" cli argument
func setupCpuprofile(cpuprofileArg string) func() {
	tlog.Info.Printf("Writing CPU profile to %s", cpuprofileArg)
	f, err := os.Create(cpuprofileArg)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Profiler)
	}
	err = pprof.StartCPUProfile(f)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Profiler)
	}
	return func() {
		pprof.StopCPUProfile()
	}
}

// setupTrace is called to handle a non-empty "-memprofile" cli argument
func setupMemprofile(memprofileArg string) func() {
	tlog.Info.Printf("Will write memory profile to %q", memprofileArg)
	f, err := os.Create(memprofileArg)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Profiler)
	}
	exiting := false
	// Write the memory profile to disk every 60 seconds to get the in-use
	// memory stats.
	go func() {
		for {
			time.Sleep(60 * time.Second)
			if exiting {
				return
			}
			_, err = f.Seek(0, 0)
			if err != nil {
				tlog.Warn.Printf("memprofile: Seek failed: %v", err)
				return
			}
			err = f.Truncate(0)
			if err != nil {
				tlog.Warn.Printf("memprofile: Truncate failed: %v", err)
				return
			}
			err = pprof.WriteHeapProfile(f)
			if err == nil {
				tlog.Info.Printf("memprofile: periodic write to %q succeeded",
					memprofileArg)
			} else {
				tlog.Warn.Printf("memprofile: periodic WriteHeapProfile failed: %v", err)
				return
			}
		}
	}()
	// Final write on exit.
	return func() {
		exiting = true
		err = pprof.WriteHeapProfile(f)
		if err != nil {
			tlog.Warn.Printf("memprofile: on-exit WriteHeapProfile failed: %v", err)
		}
		f.Close()
	}
}

// setupTrace is called to handle a non-empty "-trace" cli argument
func setupTrace(traceArg string) func() {
	tlog.Info.Printf("Writing execution trace to %s", traceArg)
	f, err := os.Create(traceArg)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Profiler)
	}
	err = trace.Start(f)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Profiler)
	}
	return func() {
		trace.Stop()
	}
}
