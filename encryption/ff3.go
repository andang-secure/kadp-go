package encryption

import (
	"fmt"
	"github.com/capitalone/fpe/ff3"
	"log"
)

func ff3Encrypt(plaintext, key, tweak string, radix, start, end int) (string, error) {

	encrypter, err := ff3.NewCipher(radix, []byte(key), []byte(tweak))
	if err != nil {
		fmt.Println("Failed to create FF1 encrypter:", err)
		return "", err
	}
	var middle string
	var before string
	var after string

	if (start + end) != 0 {
		before = plaintext[:start-1]
		middle = plaintext[start-1 : end]
		after = plaintext[end:]
	} else {
		middle = plaintext
	}
	ciphertext, err := encrypter.Encrypt(middle)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return "", err
	}

	return before + ciphertext + after, err
}

func ff3Decrypt(ciphertext, key, tweak string, radix, start, end int) (string, error) {

	// 创建 FF1 解密器
	decrypter, err := ff3.NewCipher(radix, []byte(key), []byte(tweak))
	if err != nil {
		log.Println("Failed to create FF1 decrypter:", err)
		return "", err
	}
	var middle string
	var before string
	var after string

	if (start + end) != 0 {
		before = ciphertext[:start-1]
		middle = ciphertext[start-1 : end]
		after = ciphertext[end:]
	} else {
		middle = ciphertext
	}
	// 解密字符串
	decryptedText, err := decrypter.Decrypt(middle)
	if err != nil {
		log.Println("Decryption failed:", err)
		return "", err
	}

	return before + decryptedText + after, nil
}
