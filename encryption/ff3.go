package encryption

import (
	"fmt"
	"github.com/capitalone/fpe/ff3"
	"log"
)

func ff3Encrypt(plaintext, key, tweak string, radix int) (string, error) {

	encrypter, err := ff3.NewCipher(radix, []byte(key), []byte(tweak))
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

	return "", err
}

func ff3Decrypt(ciphertext, key, tweak string, radix int) (string, error) {

	// 创建 FF1 解密器
	decrypter, err := ff3.NewCipher(radix, []byte(key), []byte(tweak))
	if err != nil {
		log.Println("Failed to create FF1 decrypter:", err)
		return "", err
	}

	// 解密字符串
	decryptedText, err := decrypter.Decrypt(ciphertext)
	if err != nil {
		log.Println("Decryption failed:", err)
		return "", err
	}

	return decryptedText, nil
}
