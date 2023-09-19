package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/capitalone/fpe/ff1"
)

func ff1Encrypt(plaintext, key string, radix int) (string, error) {

	tweak := make([]byte, 16)
	_, err := rand.Read(tweak)
	if err != nil {
		return "", err
	}
	tweak, err = hex.DecodeString(string(tweak))

	encrypter, err := ff1.NewCipher(radix, 8, []byte(key), tweak)
	if err != nil {
		fmt.Println("Failed to create FF1 encrypter:", err)
		return "", err
	}

	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return "", err
	}
	fmt.Println("Ciphertext:", ciphertext)
	return ciphertext, nil
}

func ff1Decrypt(ciphertext, key string, radix int) (string, error) {

	tweak := make([]byte, 16)
	_, err := rand.Read(tweak)
	if err != nil {
		return "", err
	}
	tweak, err = hex.DecodeString(string(tweak))

	decrypter, err := ff1.NewCipher(radix, 8, []byte(key), tweak)
	if err != nil {
		fmt.Println("Failed to create FF1 decrypter:", err)
		return "", err
	}

	// 解密字符串
	decryptedText, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return "", err
	}
	fmt.Println("Decrypted text:", decryptedText)
	return decryptedText, nil
}
