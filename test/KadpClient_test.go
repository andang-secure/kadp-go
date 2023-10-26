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
	myClient := encryption.NewKADPClient(url, token)

	encrypt, err := myClient.FpeEncipher("151918123", algorithm.FF3, "12345678", 36, 16, "kadp112", 2, 6)
	if err != nil {
		fmt.Println(err)
	}
	log.Println(encrypt)

	fmt.Println("密文" + encrypt)
	asdas := "asd密文"
	decipher, err := myClient.FpeDecipher(encrypt, algorithm.FF3, "12345678", 36, 16, "kadp112", 2, 6)
	fmt.Println(decipher)

	encipher, err := myClient.Encipher([]byte(asdas), algorithm.DES, mode.CBC, padding.NoPadding, 16, "awd1", "12345678")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, algorithm.DES, mode.CBC, padding.NoPadding, 16, "awd1", "12345678")
	fmt.Println(plaintext)

	if err != nil {
		return
	}
	fmt.Println("解密" + decipher)
	log.Println(decipher)

	pub, pri, err := myClient.AsymmetricKeyPair(algorithm.RSA)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥：", pub)
	fmt.Println("私钥：", pri)

	publicEncrypt, err := myClient.AsymmetricPubEncrypt("文档是我的", algorithm.RSA, pub)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥加密过后密文：", publicEncrypt)

	decrypt, err := myClient.AsymmetricPriDecrypt(publicEncrypt, algorithm.RSA, pri)
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
