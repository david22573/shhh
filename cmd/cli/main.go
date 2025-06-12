package main

import (
	"fmt"
	"os"

	"github.com/david22573/shhh/internal/vault"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shhh <init|unlock> <vault.shh>")
		return
	}

	cmd := os.Args[1]
	file := os.Args[2]

	switch cmd {
	case "init":
		fmt.Print("Enter password: ")
		var password string
		fmt.Scanln(&password)

		// Sample secret data
		secrets := []byte(`{"secrets":[{"name":"API_KEY","value":"sk-xyz"}]}`)

		err := vault.CreateVault(file, password, secrets)
		if err != nil {
			fmt.Println("Failed to create vault:", err)
			return
		}
		fmt.Println("Vault created:", file)

	case "unlock":
		fmt.Print("Enter password: ")
		var password string
		fmt.Scanln(&password)

		plaintext, err := vault.UnlockVault(file, password)
		if err != nil {
			fmt.Println("Failed to unlock vault:", err)
			return
		}
		fmt.Println("Vault contents:\n", string(plaintext))

	default:
		fmt.Println("Unknown command:", cmd)
	}
}
