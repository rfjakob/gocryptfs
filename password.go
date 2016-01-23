package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func readPasswordTwice(extpass string) string {
	if extpass == "" {
		fmt.Printf("Password: ")
		p1 := readPassword("")
		fmt.Printf("Repeat: ")
		p2 := readPassword("")
		if p1 != p2 {
			fmt.Println(colorRed + "Passwords do not match" + colorReset)
			os.Exit(ERREXIT_PASSWORD)
		}
		return p1
	} else {
		return readPassword(extpass)
	}
}

// readPassword - get password from terminal
// or from the "extpass" program
func readPassword(extpass string) string {
	var password string
	var err error
	var output []byte
	if extpass != "" {
		parts := strings.Split(extpass, " ")
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Stderr = os.Stderr
		output, err = cmd.Output()
		if err != nil {
			fmt.Printf(colorRed+"extpass program returned error: %v\n"+colorReset, err)
			os.Exit(ERREXIT_PASSWORD)
		}
		// Trim trailing newline like terminal.ReadPassword() does
		if output[len(output)-1] == '\n' {
			output = output[:len(output)-1]
		}
	} else {
		fd := int(os.Stdin.Fd())
		output, err = terminal.ReadPassword(fd)
		if err != nil {
			fmt.Printf(colorRed+"Could not read password from terminal: %v\n"+colorReset, err)
			os.Exit(ERREXIT_PASSWORD)
		}
		fmt.Printf("\n")
	}
	password = string(output)
	if password == "" {
		fmt.Printf(colorRed + "Password is empty\n" + colorReset)
		os.Exit(ERREXIT_PASSWORD)
	}
	return password
}
