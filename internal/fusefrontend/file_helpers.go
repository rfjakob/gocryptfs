package fusefrontend

import "fmt"

func (f *File) GetIdentifier() (uint64, uint8, uint64) {
  return f.qIno.Dev, f.qIno.Tag, f.qIno.Ino
}

func (f *File) GetAuditPayload() map[string]string {
  m := make(map[string]string)
  fDev, fTag, fIno := f.GetIdentifier()
  m["file"] = fmt.Sprintf("[%d, %d, %d]", fDev, fTag, fIno)
  return m
}
