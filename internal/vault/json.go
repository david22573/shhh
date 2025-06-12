package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Encrypts and writes to json
func CreateJsonVault(filename, password string, plaintext []byte) error {
	salt := make([]byte, 16)
	rand.Read(salt)

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	vault := VaultFile{
		Version:    1,
		Created:    time.Now().UTC().Format(time.RFC3339),
		KDF:        "argon2id",
		Salt:       b64(salt),
		Nonce:      b64(nonce),
		Ciphertext: b64(ciphertext),
	}

	data, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

// Decrypts and returns plaintext
func UnlockJSONVault(filename, password string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var vault VaultFile
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, err
	}

	salt := fromB64(vault.Salt)
	nonce := fromB64(vault.Nonce)
	ciphertext := fromB64(vault.Ciphertext)

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	return plaintext, nil
}
