package netcode

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

// Generates random bytes
func RandomBytes(bytes int) ([]byte, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	return b, err
}

// Generates a random key of KEY_BYTES
func GenerateKey() ([]byte, error) {
	return RandomBytes(KEY_BYTES)
}

// Encrypts the message in place with the nonce and key and optional additional buffer
// Uses small nonce 12 bytes
func EncryptAead(message []byte, additional, nonce, key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	aead.Seal(message[:0], nonce, message, additional)
	return nil
}

// Encrypts the message in place with the nonce and key and optional additional buffer
// Uses large nonce 24 bytes
func EncryptAeadX(message []byte, additional, nonce, key []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	aead.Seal(message[:0], nonce, message, additional)
	return nil
}

// Decrypts the message with the nonce and key and optional additional buffer returning a copy
// byte slice
// Uses small nonce 12 bytes
func DecryptAead(message []byte, additional, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	message, err = aead.Open(message[:0], nonce, message, additional)
	return message, err
}

// Decrypts the message with the nonce and key and optional additional buffer returning a copy
// byte slice
// Uses large nonce 24 bytes
func DecryptAeadX(message []byte, additional, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	message, err = aead.Open(message[:0], nonce, message, additional)
	return message, err
}
