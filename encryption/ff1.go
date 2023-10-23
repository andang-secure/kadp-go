package encryption

import (
	"fmt"
	"github.com/capitalone/fpe/ff1"
)

func ff1Encrypt(plaintext, key, tweak string, radix int) (string, error) {

	encrypter, err := ff1.NewCipher(radix, 8, []byte(key), []byte(tweak))
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

func ff1Decrypt(ciphertext, key, tweak string, radix int) (string, error) {

	decrypter, err := ff1.NewCipher(radix, 8, []byte(key), []byte(tweak))
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
