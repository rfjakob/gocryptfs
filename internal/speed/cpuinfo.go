package speed

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

// cpuModelName returns the "model name" acc. to /proc/cpuinfo, or ""
// on error.
//
// Examples: On my desktop PC:
//
//	$ grep "model name" /proc/cpuinfo
//	model name	: Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
//
// --> Returns "Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz".
//
// On a Raspberry Pi 4:
//
//	$ grep "model name" /proc/cpuinfo
//	(empty)
//	$ grep Hardware /proc/cpuinfo
//	Hardware	: BCM2835
//
// --> Returns "BCM2835"
func cpuModelName() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	content, err := ioutil.ReadAll(f)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(content), "\n")
	// Look for "model name", then for "Hardware" (arm devices don't have "model name")
	for _, want := range []string{"model name", "Hardware"} {
		for _, line := range lines {
			if strings.HasPrefix(line, want) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) != 2 {
					continue
				}
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
