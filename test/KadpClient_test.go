package test

import (
	"fmt"
	"github.com/andang-security/kadp-go/kadp"
	"github.com/go-irain/logger"
	"log"
	"testing"
)

func TestKadp(t *testing.T) {

	url := "https://192.168.0.190:8090"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEDpPYO1M/Hr6lfNuCmfL+Du6ijtN0EwQ4ph9Khbyk/RSj0uZTs4kQCe+Dg5Rq8zBS92LJmcxUNPJb/XKi36TIYSXjsQmmZtnkmyrC10i67uO59OF/Ea9t7AsoF78ytTjPagSJH4iI3zXYUzwhgtxwsybTlBCs1NjP3ht3VT2BvKo3HakFvinHnBseEwwTKT0HdfB0So1+6YPEikKis5ejs7Pyuh9rAIEiA0NmriDFtVvF9Hqq+wZn97ZE1n6ewCXAT0vqH8egm4KqDpxfdLME+4sy7nBU5bDG20HfYG7+7BsMb/c3+8Cq1TT8oynJbZCBg=="
	myClient, err := kadp.NewKADPClient(url, token, "keystore.jks", "123456")

	if err != nil {
		fmt.Println(err)
	}
	str := "15191812322"
	encrypt, err := myClient.FpeEncipher(str, kadp.FF1, "1234567", "0123456789", 16, "kadp112", 2, 7)
	if err != nil {
		fmt.Println(err)
	}
	log.Println(encrypt)

	fmt.Println("FPE密文" + encrypt)
	asdas := "asd密文"
	decipher, err := myClient.FpeDecipher(encrypt, kadp.FF1, "1234567", "0123456789", 16, "kadp112", 2, 7)
	fmt.Println("FPE明文：" + decipher)

	encipher, err := myClient.Encipher([]byte(asdas), kadp.SM4, kadp.CBC, kadp.NoPadding, 16, "kadp112", "12345678")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, kadp.SM4, kadp.CBC, kadp.NoPadding, 16, "kadp112", "12345678")

	if err != nil {
		return
	}
	fmt.Println("解密" + plaintext)
	log.Println(plaintext)

	pub, pri, err := myClient.AsymmetricKeyPair(kadp.SM2)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥：", pub)
	fmt.Println("私钥：", pri)

	publicEncrypt, err := myClient.AsymmetricPubEncrypt("文档是我的", kadp.SM2, pub)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥加密过后密文：", publicEncrypt)

	decrypt, err := myClient.AsymmetricPriDecrypt(publicEncrypt, kadp.SM2, pri)
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

	hmacwd, err := myClient.Hmac([]byte("1234"), "kadp112", 16)
	if err != nil {
		fmt.Println(err)
	}
	logger.Debug("Hmac值：", hmacwd)

	hmacVerify, err := myClient.HmacVerify([]byte("1234"), hmacwd, "kadp112", 16)
	if err != nil {
		fmt.Println(err)
	}
	logger.Debug("验证Hmac成功：", hmacVerify)

	SHA1Val, err := myClient.SHASum([]byte("1234"), kadp.Sha1)
	if err != nil {
		fmt.Println(err)
	}
	logger.Debug("SHA1计算：", SHA1Val)

	SHA256Val, err := myClient.SHASum([]byte("1234"), kadp.Sha256)
	if err != nil {
		fmt.Println(err)
	}
	logger.Debug("SHA256计算：", SHA256Val)
}
