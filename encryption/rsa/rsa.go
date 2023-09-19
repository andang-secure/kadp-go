package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
)

type Rsa struct {
}

// NewRoleEndpoint ...
func NewRoleEndpoint() *Rsa {
	return &Rsa{}
}

func KeyGenerator() (publicKeyBase64, privateKeyBase64 string) {
	// 生成RSA密钥对
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 将公钥编码为DER格式
	publicKeyDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	// 创建公钥的PEM块
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	// 将公钥PEM块编码为字符串
	encodedPublicKey := string(pem.EncodeToMemory(publicKeyBlock))

	// 将私钥编码为PKCS1格式
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	// 创建私钥的PEM块
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	// 将私钥PEM块编码为字符串
	encodedPrivateKey := string(pem.EncodeToMemory(privateKeyBlock))

	return encodedPublicKey, encodedPrivateKey
}

func EncryptWithPublicKey(publicKey, plaintext string) (string, error) {
	// 解码公钥
	publicKeyBytes, _ := base64.StdEncoding.DecodeString(publicKey)
	publicKeyObject, _ := x509.ParsePKIXPublicKey(publicKeyBytes)
	rsaPublicKey := publicKeyObject.(*rsa.PublicKey)

	// 加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(plaintext))
	if err != nil {
		return "", err
	}

	// 返回Base64编码的密文
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptWithPrivateKey(privateKeyPEM, ciphertext string) (string, error) {
	log.Println("解密开始：" + ciphertext)
	log.Println("解密开始：" + privateKeyPEM)

	ciphertextByte, _ := base64.StdEncoding.DecodeString(ciphertext)

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		log.Println("解码PEM失败")
		return "", fmt.Errorf("解码PEM失败")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Println("解析私钥失败:", err)
		return "", err
	}

	decryptedText, err := rsa.DecryptPKCS1v15(rand.Reader, parsedKey, ciphertextByte)
	if err != nil {
		log.Println("解密失败:", err)
		return "", err
	}

	return string(decryptedText), nil
}

func ExtractBase64FromPEM(pemData string) (string, error) {
	// 解码PEM数据
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	// 提取Base64编码的部分
	base64Data := base64.StdEncoding.EncodeToString(block.Bytes)

	return base64Data, nil
}
