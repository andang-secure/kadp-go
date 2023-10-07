package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// aesEncrypt 使用AES-CBC/NoPadding模式加密数据
func aesEncrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 对明文进行填充
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	paddedPlaintext := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, len(paddedPlaintext))

	iv := make([]byte, aes.BlockSize)
	// 可以使用随机生成的IV，或者使用固定的IV
	// 如果使用固定的IV，请确保每次加密的IV都是唯一的
	// 如果使用随机生成的IV，请确保在解密时将IV与密文一起传递
	copy(iv, key) // 这里示例简化，将IV设置为密钥

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return cipherTextBase64, nil
}

// aseDecrypt  使用AES-CBC/NoPadding模式解密数据
func aseDecrypt(ciphertext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	// 这里示例简化，将IV设置为密钥
	copy(iv, key)

	textByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(textByte))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, textByte)

	// 去除填充数据
	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]

	return string(plaintext), nil
}
