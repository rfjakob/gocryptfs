package audit_log

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const auditLogPath = "/tmp/current_audit_log"

// Define as enum to make sure that no undefined events can be written out
type AuditEvent int
const (
  // Synthetic events
  EventStartAuditTrail AuditEvent = iota
  EventEndAuditTrail AuditEvent = iota
  EventProhibitedPathPrefix = iota
  EventProhibitedCaller = iota

  // FUSE events
  EventOpen AuditEvent = iota
  EventCreate AuditEvent = iota
  EventRelease AuditEvent = iota
  EventRead AuditEvent = iota
  EventReadlink AuditEvent = iota
  EventWrite AuditEvent = iota
  EventRename AuditEvent = iota
  EventUnlink AuditEvent = iota
  EventLseek AuditEvent = iota
  EventAllocate AuditEvent = iota
  EventMkdir AuditEvent = iota
  EventRmdir AuditEvent = iota
  EventMknod AuditEvent = iota
  EventLink AuditEvent = iota
  EventSymlink AuditEvent = iota
)
var eventName = map[AuditEvent]string {
  EventStartAuditTrail: "startAuditTrail",
  EventEndAuditTrail: "endAuditTrail",
  EventProhibitedPathPrefix: "prohibitedPathPrefix",
  EventProhibitedCaller: "prohibitedCaller",

  EventOpen: "open",
  EventCreate: "create",
  EventRelease: "release",
  EventRead: "read",
  EventReadlink: "readlink",
  EventWrite: "write",
  EventRename: "rename",
  EventUnlink: "unlink",
  EventLseek: "lseek",
  EventAllocate: "allocate",
  EventMkdir: "mkdir",
  EventRmdir: "rmdir",
  EventMknod: "mknod",
  EventLink: "link",
  EventSymlink: "symlink",
}
func (ae AuditEvent) String() string {
  return eventName[ae]
}

// Lets manually build the JSON, in order to make sure that it'll forever keep
// newline delimited
const baseJsonString = "{\"eventType\": \"%s\", \"timestamp\": \"%s\", %s \"payload\": %s}"

func formatCaller(ctx *fuse.Context) string {
  if ctx == nil {
    return ""
  }
  caller_str, err := GetCallerProcess(ctx)
  if (err != nil) {
    caller_str = "" // already logged before, I dont have a better idea
  }
  return fmt.Sprintf(
    "\"context\": {\"pid\": %d, \"uid\": %d, \"gid\": %d, \"caller_process\": \"%s\"}",
    ctx.Pid, ctx.Uid, ctx.Gid, caller_str)
}

func formatMap(m map[string]string) string {
  if m == nil || len(m) == 0 {
    return "[]"
  }
  var sb strings.Builder
  n := len(m)
  i := 0
  sb.WriteString("[")
  for key, value := range m {
    i++
    sb.WriteString(fmt.Sprintf("\"%s\": \"%s\"", key, value))
    if i < n {
      sb.WriteString(", ")
    }
  }
  sb.WriteString("]")
  return sb.String()
}

func formatEvent(etype AuditEvent, ctx *fuse.Context, m map[string]string) string {
  timestamp := time.Now().Format("2006-01-02T15:04:05")
  return fmt.Sprintf(baseJsonString, etype, timestamp, formatCaller(ctx), formatMap(m))
}

type auditHandle struct {
  mu sync.Mutex
  fileHandle *os.File
}

var globalHandle auditHandle

func StartAuditTrail() error {
	var err error
	globalHandle.fileHandle, err = os.OpenFile(auditLogPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
    tlog.Fatal.Printf("Failed to open or create audit log file: %v", err)
    return err
	}
  if err := WriteAuditEvent(EventStartAuditTrail, nil, nil); err != nil {
		return err
	}
  return nil
}

/*
This is the resulting event (unminified)
```
{
  "eventType": "SomeIdentifier",
  "timestamp": "2025-02-17T11:48:00",
  "context": { // Only existing if it is a FUSE event
    "uid": 1337,
    "pid": 1000,
    "gid": 1000,
    "caller_process": "/usr/bin/cat"
  },
  "payload": [
    // Optional payload, based on event
  ]
}
```
`ctx` maps to "context", `payload` to "payload"
 */
func WriteAuditEvent(etype AuditEvent, ctx *fuse.Context, payload map[string]string) error {
	if globalHandle.fileHandle == nil {
    // Either false call order (unlikely) or concurrent write-after-close (bad)
    error_str := "WriteAuditEvent called on nil fileHandle"
    tlog.Fatal.Println(error_str)
    return errors.New(error_str)
	}
  globalHandle.mu.Lock()
  defer globalHandle.mu.Unlock()
  str := formatEvent(etype, ctx, payload)
	_, err := globalHandle.fileHandle.WriteString(str + "\n")
	if err != nil {
		tlog.Fatal.Printf("Failed to write audit event: %v", err)
    return err;
	}
  return nil;
}

func EndAuditTrail() error {
  if err := WriteAuditEvent(EventEndAuditTrail, nil, nil); err != nil {
		return err
	}

  // we should await any currently still run events
  globalHandle.mu.Lock()
  defer globalHandle.mu.Unlock()

  err := globalHandle.fileHandle.Close()
	if err != nil {
		tlog.Fatal.Printf("Failed to close audit trail: %v", err)
	}
	globalHandle.fileHandle = nil
	return nil
}
