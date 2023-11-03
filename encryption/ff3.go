package encryption

import (
	"fmt"
	"gitlab.com/ubiqsecurity/ubiq-fpe-go"
	"log"
)

func ff3Encrypt(plaintext, key, tweak string, radix, start, end int, alphabet ...interface{}) (string, error) {

	ff3, err := ubiq.NewFF3_1([]byte(key), []byte(tweak), radix, alphabet...)
	if err != nil {
		fmt.Println("Failed to create FF3 encrypter:", err)
		return "", err
	}
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
	ciphertext, err := ff3.Encrypt(middle, nil)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return "", err
	}

	return before + ciphertext + after, err
}

//
//func ff3Encrypt(plaintext, key, tweak string, radix, start, end int) (string, error) {
//
//	encrypter, err := ff3.NewCipher(radix, []byte(key), []byte(tweak))
//	if err != nil {
//		fmt.Println("Failed to create FF1 encrypter:", err)
//		return "", err
//	}
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
//	ciphertext, err := encrypter.Encrypt(middle)
//	if err != nil {
//		fmt.Println("Encryption failed:", err)
//		return "", err
//	}
//
//	return before + ciphertext + after, err
//}
//
//func ff3Decrypt(ciphertext, key, tweak string, radix, start, end int) (string, error) {
//
//	// 创建 FF1 解密器
//	decrypter, err := ff3.NewCipher(radix, []byte(key), []byte(tweak))
//	if err != nil {
//		log.Println("Failed to create FF1 decrypter:", err)
//		return "", err
//	}
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
//		log.Println("Decryption failed:", err)
//		return "", err
//	}
//
//	return before + decryptedText + after, nil
//}

func ff3Decrypt(ciphertext, key, tweak string, radix, start, end int, alphabet ...interface{}) (string, error) {

	// 创建 FF1 解密器
	ff3, err := ubiq.NewFF3_1([]byte(key), []byte(tweak), radix, alphabet...)
	if err != nil {
		log.Println("Failed to create FF3 decrypter:", err)
		return "", err
	}
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
	// 解密字符串
	decryptedText, err := ff3.Decrypt(middle, nil)
	if err != nil {
		log.Println("Decryption failed:", err)
		return "", err
	}

	return before + decryptedText + after, nil
}
