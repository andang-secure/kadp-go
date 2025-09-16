package aes_alg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
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

func AesCBCDecryptNoPad(cipherText, key, iv []byte) ([]byte, error) {
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
	return plainText, nil
}

// AesDecrypt 解密
func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	var err2 error = nil
	defer func() {
		if r := recover(); r != nil {
			err2 = fmt.Errorf("%v", r)
		}
	}()
	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//初始化解密数据接收切片
	encrypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(encrypted, data)
	//去除填充
	encrypted, err = pkcs7UnPadding(encrypted)
	if err != nil {
		return nil, err
	}
	return encrypted, err2
}

// pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}
