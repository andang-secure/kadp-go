package encryption

import (
	"fmt"
	"gitlab.com/ubiqsecurity/ubiq-fpe-go"
)

func ff1Encrypt(plaintext, key, tweak string, radix, start, end int, alphabet ...interface{}) (string, error) {

	ff1, err := ubiq.NewFF1([]byte(key), []byte(tweak), 0, 0, radix, alphabet...)
	if err != nil {
		return "", err
	}

	if err != nil {
		fmt.Println("Failed to create FF1 encrypter:", err)
		return "", err
	}
	fmt.Println("开始加密:-----")

	//
	var middle string
	var before string
	var after string

	if (start + end) != 0 {

		before = extractSubString(plaintext, 0, start-1)
		middle = extractSubString(plaintext, start-1, end)
		after = extractSubString(plaintext, end, len(plaintext))
	} else {
		middle = plaintext
	}

	fmt.Println("开始加密:-----", middle)

	ciphertext, err := ff1.Encrypt(middle, nil)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return "", err
	}
	fmt.Println("Ciphertext:", ciphertext)

	return before + ciphertext + after, nil
}

//
//func ff1Encrypt(plaintext, key, tweak string, radix int, start, end int) (string, error) {
//
//	encrypter, err := ff1.NewCipher(radix, 8, []byte(key), []byte(tweak))
//	if err != nil {
//		fmt.Println("Failed to create FF1 encrypter:", err)
//		return "", err
//	}
//	//
//	var middle string
//	var before string
//	var after string
//
//	if (start + end) != 0 {
//		before = plaintext[:start-1]
//		middle = plaintext[start-1 : end]
//		after = plaintext[end:]
//	} else {
//		middle = plaintext
//	}
//
//	ciphertext, err := encrypter.Encrypt(middle)
//	if err != nil {
//		fmt.Println("Encryption failed:", err)
//		return "", err
//	}
//	fmt.Println("Ciphertext:", ciphertext)
//
//	return before + ciphertext + after, nil
//}

//func ff1Decrypt(ciphertext, key, tweak string, radix int, start, end int) (string, error) {
//
//	decrypter, err := ff1.NewCipher(radix, 8, []byte(key), []byte(tweak))
//	if err != nil {
//		fmt.Println("Failed to create FF1 decrypter:", err)
//		return "", err
//	}
//
//	//
//	var middle string
//	var before string
//	var after string
//
//	if (start + end) != 0 {
//		before = ciphertext[:start-1]
//		middle = ciphertext[start-1 : end]
//		after = ciphertext[end:]
//	} else {
//		middle = ciphertext
//	}
//	// 解密字符串
//	decryptedText, err := decrypter.Decrypt(middle)
//	if err != nil {
//		fmt.Println("Decryption failed:", err)
//		return "", err
//	}
//	fmt.Println("Decrypted text:", decryptedText)
//	return before + decryptedText + after, nil
//}

func ff1Decrypt(ciphertext, key, tweak string, radix, start, end int, alphabet ...interface{}) (string, error) {

	ff1, err := ubiq.NewFF1([]byte(key), []byte(tweak), 0, 0, radix, alphabet...)
	if err != nil {
		fmt.Println("Failed to create FF1 decrypter:", err)
		return "", err
	}

	//
	var middle string
	var before string
	var after string
	if (start + end) != 0 {
		before = extractSubString(ciphertext, 0, start-1)
		middle = extractSubString(ciphertext, start-1, end)
		after = extractSubString(ciphertext, end, len(ciphertext))
	} else {
		middle = ciphertext
	}

	fmt.Println("头", before)
	fmt.Println("中", middle)

	fmt.Println("尾部", after)

	// 解密字符串
	decryptedText, err := ff1.Decrypt(middle, nil)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return "", err
	}

	fmt.Println("Decrypted text:", decryptedText)
	return before + decryptedText + after, nil
}

func extractSubString(str string, start int, end int) string {
	runes := []rune(str)
	if start >= len(runes) || start >= end {
		return ""
	}
	if end > len(runes) {
		end = len(runes)
	}

	return string(runes[start:end])
}
