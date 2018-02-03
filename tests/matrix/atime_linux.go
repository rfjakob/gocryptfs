package matrix

import (
	"golang.org/x/sys/unix"
)

func extractAtimeMtime(st unix.Stat_t) [2]unix.Timespec {
	return [2]unix.Timespec{st.Atim, st.Mtim}
}
