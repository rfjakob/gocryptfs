package audit_log

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func GetCallerProcess(ctx2 *fuse.Context) (string, error) {
  buf := make([]byte, syscallcompat.PATH_MAX)
  pid_path := fmt.Sprintf("/proc/%d/exe", ctx2.Pid)
  num, err := syscall.Readlink(pid_path, buf)
  if (err != nil) {
    error_str := fmt.Sprintf("read process name failed w/ '%s'", err)
    tlog.Warn.Println(error_str)
    return "", errors.New(error_str)
  }
  return string(buf[:num]), nil
}
