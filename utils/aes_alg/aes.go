package aes_alg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	BlockSize = 16
)

func AesCBCEncrypt(plainText, key, iv []byte) (cipherText []byte, err error) {
	plainText = getPaddingData(plainText, BlockSize)
	//plainText = pkcs5Padding(plainText, BlockSize)
	plainTextLen := len(plainText)
	if plainTextLen%BlockSize != 0 {
		return nil, errors.New("input not full blocks")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypt := cipher.NewCBCEncrypter(c, iv)
	cipherText = make([]byte, plainTextLen)
	encrypt.CryptBlocks(cipherText, plainText)
	return cipherText, nil
}
func AesCBCDecrypt(cipherText, key, iv []byte) ([]byte, error) {
	cipherTextLen := len(cipherText)
	if cipherTextLen%BlockSize != 0 {
		return nil, errors.New("input not full blocks")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypt := cipher.NewCBCDecrypter(c, iv)
	plainText := make([]byte, len(cipherText))
	decrypt.CryptBlocks(plainText, cipherText)
	plainText = getUnPaddingData(plainText)
	return plainText, nil
}
func getPaddingData(origData []byte, blockSize int) []byte {

	origData = pkcs5Padding(origData, blockSize)

	return origData
}

func getUnPaddingData(origData []byte) []byte {

	origData = pkcs5UnPadding(origData)

	return origData
}

func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])
	if length < unPadding {
		return nil
	}
	return src[:(length - unPadding)]
}
