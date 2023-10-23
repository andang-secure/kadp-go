package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// aesEncrypt 使用AES-CBC/NoPadding模式加密数据
func aseCbcNoPadEncrypt(plaintext []byte, key []byte, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 对明文进行填充
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	paddedPlaintext := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, len(paddedPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return cipherTextBase64, nil
}

// aseDecrypt  使用AES-CBC/NoPadding模式解密数据
func aseCbcNoPadDecrypt(ciphertext string, key []byte, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

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

func aseCbcPKCS5Encrypt(plaintext []byte, key []byte, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	plaintext = aesPKCS5Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)
	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return cipherTextBase64, nil
}

func aseCbcPKCS5Decrypt(ciphertext string, key []byte, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	textByte, err := base64.StdEncoding.DecodeString(ciphertext)

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(textByte))
	blockMode.CryptBlocks(origData, textByte)
	origData = aesPKCS5UnPadding(origData)
	return string(origData), nil
}

func aesPKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aesPKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
