package test

import (
	"fmt"
	"github.com/andang-secure/kadp-go/kadp"
	"github.com/go-irain/logger"
	"log"
	"testing"
)

func TestKadp(t *testing.T) {

	//url := "https://127.0.0.1:8090"
	//token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKesS0JhbLLai/aJeKzdyq79J9VrY9WrZIb9CbEm4Ivsoi23z/8h+ZpNbPnRSrQcDp5Ad7EXJR30thzPxt9vzRTjElJ0bqppU9TQJDgRqKcF3Zx0nx2fynzTZabN/EKSbcw=="
	//myClient, err := kadp.NewKADPClient(url, token, "QVSxoBH+SsUH9Vl3UC3D7YGV4tw5vaI7T/joivh/7FECvH06rcTwJvHjxvzdy8cD", "keystore.jks", "123456")

	url := "https://192.168.0.192"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKWyPkTDAgePhK8OQvIyF5gFGnFYd/Fu2RY76GnJFqftOZhM6fg5K/7dBMa1jKkMwt6FuG61Kq7VXgobTJ+TZt/MXO/AiI0Z9WS3BpaMMyHRF/NyYFsPM/SpfLTNFGdTt1orN5o/IpXm/c4IicLobzqByvKfTYeA7ee5cKA0BxLy1H3uYabALKDa+7A2DK0Q97Q=="
	myClient, err := kadp.NewKADPClient(url, token, "l/Snh3ZdgjuslYfNJz//MpeBHa33plU9hgTSI0wKd27dIqrVJ/qLPuusSDjnMHr+", "keystore.jks", "123456")

	//url := "https://192.168.0.135"
	//token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEGIr3RnQLyJOw/V3WgJRDWtvp4u+t85j0tjhpItzfPZsxD2X+aswNvd/UXEPvxU1daxJUCPZyeBXty1QVdycOUd6QNTBau0xytKFrfVDWbyMrNYFnfiH++ecgAU9kcw4S+KnZQ1fH+OyrWft4nkEsSXKzKWSo3V1H5OXAwsCohhD5eYPGhttprdgcJEOcFd1vt1+rzrr35gQ5Bq1IeqkN9D4H0CtqmZ+9PTIlsDvspUxvvhh1Z2gezc9gHIC9lvyzAOWS5q+hfiUPR1ZX4uoTVOoppRJRwtHwczNSAPrXN8uyCQSHhrJDduE4AHwwWGSrBltkSOLM/S1GrYH73nKel5NAAEAQs3CL5bWbdIXsG8dirS/1UiTD7IL1FwCFqyIPHVXXSSoPL4ASbwZYOZx2DAWctFQqTb/fohr0uqaVnn1"
	//myClient, err := kadp.NewKADPClient(url, token, "N9YSgmHFvDoZXCmTulJ+LkR1q0b0ZDjIdzPJaj/+JATJfub9ganNzglsHakEwE3E", "keystore.jks", "123456")

	if err != nil {
		fmt.Println(err)
	}
	str := "15191812322"
	encrypt, err := myClient.FpeEncipher(str, kadp.FF1, "1234567", "0123456789", 16, "kadp1123122", 1, +8)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("FPE密文" + encrypt)
	asdas := "asd密文是是1"
	decipher, err := myClient.FpeDecipher(encrypt, kadp.FF1, "1234567", "0123456789", 16, "kadp1123122", 1, 8)
	fmt.Println("FPE明文：" + decipher)

	encipher, err := myClient.Encipher([]byte(asdas), kadp.SM4, kadp.ECB, kadp.ISO10126Padding, 16, "kadp112", "12345678912345678")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, kadp.SM4, kadp.ECB, kadp.ISO10126Padding, 16, "kadp112", "12345678912345678")

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
	publa := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE6uPJNtK5mFj8QjUSJd2/R0Zag4k0\ndpQoTLkyX/8UuyTqGuZK35qR5/qQOJot01M9gAIowUokTxWobQ8mTnE28Q==\n-----END PUBLIC KEY-----"

	publicEncrypt, err := myClient.AsymmetricPubEncrypt("微信文档", kadp.SM2, publa)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("公钥加密过后密文：", publicEncrypt)

	sadd := "MHYCIQCSJTNUY/upuKc9/MW6cVLlnUO8O4/2p1eq+gkpbKnW2gIhAJqKw1y1Fu1eQ9bMHyjd4rAe8L280gI8AuWQj34aBLXOBCBQat5J4r/cYKxKJ53qm2rywjpdw7+UKOCWxNP51gXGkQQMgEW9q4OQRQVY6wua"
	decrypt, err := myClient.AsymmetricPriDecrypt(sadd, kadp.SM2, pri)
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
