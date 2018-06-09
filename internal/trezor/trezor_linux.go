// +build linux

package trezor

import (
	"log"
	"os"
	"syscall"
	"time"

	"github.com/conejoninja/tesoro/transport"
	"github.com/zserge/hid"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
)


func (trezor *trezor) Reconnect() {
	success := false
	for !success {
		hid.UsbWalk(func(device hid.Device) {
			info := device.Info()
			if info.Vendor == 21324 && info.Product == 1 && info.Interface == 0 {
				var t transport.TransportHID
				t.SetDevice(device)
				trezor.Client.SetTransport(&t)
				trezor.Device = device
				success = true
				return
			}
		})
		if !success {
			log.Print("No Trezor devices found.")
			trezor.pinentry.SetPrompt("No Trezor devices found.")
			trezor.pinentry.SetDesc("Please check connection to your Trezor device.")
			trezor.pinentry.SetOK("Retry")
			trezor.pinentry.SetCancel("Unmount")
			shouldContinue := trezor.pinentry.Confirm()
			if !shouldContinue {
				log.Print("Cannot continue without Trezor devices.")
				syscall.Kill(syscall.Getpid(), syscall.SIGINT)
				time.Sleep(time.Second * 5) // Waiting to interrupt signal to get things done
				os.Exit(exitcodes.SigInt)   // Just in case
			}
		} else if !trezor.Ping() {
			log.Panic("An unexpected behaviour of the trezor device.")
		}
	}
}

