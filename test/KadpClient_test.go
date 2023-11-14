package test

import (
	"fmt"
	"github.com/andang-secure/kadp-go/kadp"
	"github.com/go-irain/logger"
	"log"
	"testing"
)

func TestKadp(t *testing.T) {

	url := "https://ksp.andang.cn"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rECrvbLqyIxlmK61Yl9PjnJ+Cf1egJJ/xZ/jyq/15EjEwmCk0ksXcyy36WN0/HUyZzHuq5DVzGdP0bfFs3k0vWbJBLZ1IoNenEI+3vR6eWWZRVN/ZmvMkgygDyALsF4iAiD12aHOAJI6A5GnNsiI9xYVb+JtrU67pj2HsDKMWNFm9Krrq9+YE+goXRY07W/5G5WQxeM2ZqOAOlWXRRKOcN5gPPu7fuCgVJe2QGhsr1dmmhoX3AUqkco2Q4uEPmqc8bTO/fh7/upAaG2/FbPQNW5jOkWDyCoHG5HNTQz34HUNvILrllMG8sSIaeR/Tg8GrXQ=="
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
	asdas := "asd密文是是1"
	decipher, err := myClient.FpeDecipher(encrypt, kadp.FF1, "1234567", "0123456789", 16, "kadp112", 2, 7)
	fmt.Println("FPE明文：" + decipher)

	encipher, err := myClient.Encipher([]byte(asdas), kadp.AES, kadp.CGM, kadp.PKCS7Padding, 16, "kadp112", "1234567891234567")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, kadp.AES, kadp.CGM, kadp.PKCS7Padding, 16, "kadp112", "1234567891234567")

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
