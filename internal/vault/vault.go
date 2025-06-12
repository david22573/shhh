package vault

import (
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

type VaultFile struct {
	Version    int    `json:"version"`
	Created    string `json:"created"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`       // base64
	Nonce      string `json:"nonce"`      // base64
	Ciphertext string `json:"ciphertext"` // base64
}

// Helper: base64 encode
func b64(x []byte) string {
	return base64.StdEncoding.EncodeToString(x)
}

// Helper: base64 decode
func fromB64(s string) []byte {
	x, _ := base64.StdEncoding.DecodeString(s)
	return x
}

// Derive key using argon2id
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func CreateVault(filename, password string, plaintext []byte) error {
	return WriteBinaryVault(filename, salt, nonce, ciphertext)
}

func UnlockVault(filename, password string) ([]byte, error) {
	return ReadBinaryVault(filename, password)
}
