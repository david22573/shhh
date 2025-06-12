package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
)

func WriteBinaryVault(filename string, salt, nonce, ciphertext []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

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

	// Magic: "SHH\x01"
	_, err = f.Write([]byte{0x53, 0x48, 0x48, 0x01}) // 'S' 'H' 'H' version 1
	if err != nil {
		return err
	}

	// Salt (16 bytes)
	_, err = f.Write(salt)
	if err != nil {
		return err
	}

	// Nonce (12 bytes)
	_, err = f.Write(nonce)
	if err != nil {
		return err
	}

	// Ciphertext (rest)
	_, err = f.Write(ciphertext)
	return err
}

func ReadBinaryVault(filename, password string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if len(data) < 32 {
		return nil, fmt.Errorf("invalid vault: too short")
	}

	magic := data[:4]
	if magic[0] != 0x53 || magic[1] != 0x48 || magic[2] != 0x48 {
		return nil, fmt.Errorf("invalid vault: bad magic")
	}
	if magic[3] != 0x01 {
		return nil, fmt.Errorf("unsupported vault version: %d", magic[3])
	}

	salt := data[4:20]
	nonce := data[20:32]
	ciphertext := data[32:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}
