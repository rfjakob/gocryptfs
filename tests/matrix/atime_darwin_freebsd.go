package matrix

import (
	"syscall"
)

func extractAtimeMtime(st syscall.Stat_t) [2]syscall.Timespec {
	return [2]syscall.Timespec{st.Atimespec, st.Mtimespec}
}
