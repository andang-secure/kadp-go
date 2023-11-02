package test

import (
	"fmt"
	"github.com/andang-security/kadp-go/algorithm"
	"github.com/andang-security/kadp-go/encryption"
	"github.com/andang-security/kadp-go/mode"
	"github.com/andang-security/kadp-go/padding"
	"github.com/go-irain/logger"
	"log"
	"testing"
)

func TestAdd(t *testing.T) {

	url := "https://192.168.0.190:8090"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEDpPYO1M/Hr6lfNuCmfL+Du6ijtN0EwQ4ph9Khbyk/RSj0uZTs4kQCe+Dg5Rq8zBS92LJmcxUNPJb/XKi36TIYSXjsQmmZtnkmyrC10i67uO59OF/Ea9t7AsoF78ytTjPagSJH4iI3zXYUzwhgtxwsybTlBCs1NjP3ht3VT2BvKo3HakFvinHnBseEwwTKT0HdfB0So1+6YPEikKis5ejs7Pyuh9rAIEiA0NmriDFtVvF9Hqq+wZn97ZE1n6ewCXAT0vqH8egm4KqDpxfdLME+4sy7nBU5bDG20HfYG7+7BsMb/c3+8Cq1TT8oynJbZCBg=="
	myClient, _ := encryption.NewKADPClient(url, token)

	encrypt, err := myClient.FpeEncipher("1324abcd5648789国旗下的光辉asd·oaklamaz", algorithm.FF1, "1234567", "你木纹0123456789abcd国旗下的光辉", 16, "kadp112", 2, 18)
	if err != nil {
		fmt.Println(err)
	}
	log.Println(encrypt)

	fmt.Println("FPE密文" + encrypt)
	asdas := "asd密文"
	decipher, err := myClient.FpeDecipher(encrypt, algorithm.FF1, "1234567", "你木纹0123456789abcd国旗下的光辉", 16, "kadp112", 2, 18)
	fmt.Println("FPE明文：" + decipher)

	encipher, err := myClient.Encipher([]byte(asdas), algorithm.SM4, mode.CBC, padding.NoPadding, 16, "awd1", "12345678")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, algorithm.SM4, mode.CBC, padding.NoPadding, 16, "awd1", "12345678")

	if err != nil {
		return
	}
	fmt.Println("解密" + plaintext)
	log.Println(plaintext)

	pub, pri, err := myClient.AsymmetricKeyPair(algorithm.SM2)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥：", pub)
	fmt.Println("私钥：", pri)

	publicEncrypt, err := myClient.AsymmetricPubEncrypt("文档是我的", algorithm.SM2, pub)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥加密过后密文：", publicEncrypt)

	decrypt, err := myClient.AsymmetricPriDecrypt(publicEncrypt, algorithm.SM2, pri)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("私钥解密：", decrypt)

	r, s, err := myClient.SM2Signature("Wdswd", pri, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("签名:", r, s)

	verify, err := myClient.SM2Verify("Wdswd", pub, r, s, nil)
	if err != nil {
		fmt.Println(err)
	}
	logger.Debug("验签:", verify)

	Hash := myClient.DigestEncrypt("wdad")
	logger.Debug("摘要哈希：", Hash)
}
