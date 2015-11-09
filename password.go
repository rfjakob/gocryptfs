package main

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"os"
)

func readPasswordTwice() string {
	fmt.Printf("Password: ")
	p1 := readPassword()
	fmt.Printf("Repeat: ")
	p2 := readPassword()
	if p1 != p2 {
		fmt.Printf("Passwords do not match\n")
		os.Exit(ERREXIT_PASSWORD)
	}
	return p1
}

// Get password from terminal
func readPassword() string {
	fd := int(os.Stdin.Fd())
	p, err := terminal.ReadPassword(fd)
	fmt.Printf("\n")
	if err != nil {
		fmt.Printf("Error: Could not read password: %v\n", err)
		os.Exit(ERREXIT_PASSWORD)
	}
	return string(p)
}
