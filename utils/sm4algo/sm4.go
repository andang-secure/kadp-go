package sm4algo

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"github.com/tjfoc/gmsm/sm4"
)

const (
	BlockSize = 16
)

// Sm4CBCEncrypt 输入的plainText长度必须是BlockSize(16)的整数倍，也就是调用该方法前调用方需先加好padding，
// 可调用util.PKCS5Padding()方法进行加padding操作
func Sm4CBCEncrypt(plainText, key, iv []byte) (cipherText []byte, err error) {
	plainText = getPaddingData(plainText, BlockSize)
	//plainText = pkcs5Padding(plainText, BlockSize)
	plainTextLen := len(plainText)
	if plainTextLen%BlockSize != 0 {
		return nil, errors.New("input not full blocks")
	}

	c, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypt := cipher.NewCBCEncrypter(c, iv)
	cipherText = make([]byte, plainTextLen)
	encrypt.CryptBlocks(cipherText, plainText)
	return cipherText, nil
}

// Sm4CBCDecrypt CBCDecrypt 输出的plainText是加padding的明文，调用方需要自己去padding，
// 可调用util.PKCS5UnPadding()方法进行去padding操作
func Sm4CBCDecrypt(cipherText, key, iv []byte) (string, error) {
	cipherTextLen := len(cipherText)
	if cipherTextLen%BlockSize != 0 {
		return "", errors.New("input not full blocks")
	}

	c, err := sm4.NewCipher(key)
	if err != nil {
		return "", err
	}
	decrypt := cipher.NewCBCDecrypter(c, iv)
	plainText := make([]byte, len(cipherText))
	decrypt.CryptBlocks(plainText, cipherText)
	plainText = getUnPaddingData(plainText)
	return string(plainText), nil
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
