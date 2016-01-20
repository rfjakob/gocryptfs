package cryptfs

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
)

func JSONDump(obj interface{}) string {
	b, err := json.MarshalIndent(obj, "", "\t")
	if err != nil {
		return err.Error()
	} else {
		return string(b)
	}
}

// As defined by http://elinux.org/Debugging_by_printing#Log_Levels

// Debug messages
var Debug *log.Logger

// Informational message e.g. startup information
var Info *log.Logger

// A warning, meaning nothing serious by itself but might indicate problems
var Warn *log.Logger

func init() {
	Debug = log.New(ioutil.Discard, "", 0)
	Info = log.New(os.Stdout, "", 0)
	Warn = log.New(os.Stderr, "", 0)
}
