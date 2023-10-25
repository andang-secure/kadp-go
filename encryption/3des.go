package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
)

// 3DES解密
func tripleDesDecrypt(crypted string, key, iv []byte) (string, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}

	ciphertextDecode, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(ciphertextDecode))
	blockMode.CryptBlocks(origData, ciphertextDecode)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

// 3DES加密
func tripleDesEncrypt(origData, key, iv []byte) (string, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(origData))
	blockMode.CryptBlocks(ciphertext, origData)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return cipherTextBase64, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:length-unPadding]
}
