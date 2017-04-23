package stupidgcm

import (
	"fmt"
)

// ErrAuth is returned when the message authentication fails
var ErrAuth = fmt.Errorf("stupidgcm: message authentication failed")
