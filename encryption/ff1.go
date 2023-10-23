package encryption

import (
	"fmt"
	"github.com/capitalone/fpe/ff1"
)

func ff1Encrypt(plaintext, key, tweak string, radix int, start, end int) (string, error) {

	encrypter, err := ff1.NewCipher(radix, 8, []byte(key), []byte(tweak))
	if err != nil {
		fmt.Println("Failed to create FF1 encrypter:", err)
		return "", err
	}
	//
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
	fmt.Println("Ciphertext:", ciphertext)

	return before + ciphertext + after, nil
}

func ff1Decrypt(ciphertext, key, tweak string, radix int, start, end int) (string, error) {

	decrypter, err := ff1.NewCipher(radix, 8, []byte(key), []byte(tweak))
	if err != nil {
		fmt.Println("Failed to create FF1 decrypter:", err)
		return "", err
	}

	//
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
		fmt.Println("Decryption failed:", err)
		return "", err
	}
	fmt.Println("Decrypted text:", decryptedText)
	return before + decryptedText + after, nil
}
