package encryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/go-irain/logger"
	"log"
)

func rsaKeyGenerator() (publicKeyBase64, privateKeyBase64 string, err error) {
	// 生成RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// 将公钥编码为DER格式
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

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

	return encodedPublicKey, encodedPrivateKey, nil
}

func rsaEncryptWithPublicKey(publicKey, plaintext string) (string, error) {
	//// 解码公钥
	//publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	//if err != nil {
	//	return "", err
	//}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		logger.Error("解码PEM失败")
		return "", fmt.Errorf("解码PEM失败")
	}
	publicKeyObject, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rsaPublicKey := publicKeyObject.(*rsa.PublicKey)

	// 加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(plaintext))
	if err != nil {
		return "", err
	}

	// 返回Base64编码的密文
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func rsaDecryptWithPrivateKey(privateKeyPEM, ciphertext string) (string, error) {

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

func rsaSign(priKey string, data []byte) (sign string, err error) {

	block, _ := pem.Decode([]byte(priKey))
	if block == nil {
		log.Println("解码PEM失败")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Println("解析私钥失败:", err)
	}

	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, parsedKey, crypto.SHA256, hashed[:])

	if err != nil {

	}
	signatureText := base64.StdEncoding.EncodeToString(signature)

	return signatureText, nil

}

func rsaVerify(pubKey, signatureText string, data []byte) (bool, error) {

	// 解码公钥
	//publicKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
	//if err != nil {
	//	return false, err
	//}

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		logger.Error("解码PEM失败")
		return false, fmt.Errorf("解码PEM失败")
	}

	publicKeyObject, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	rsaPublicKey := publicKeyObject.(*rsa.PublicKey)

	signatureTextBytes, err := base64.StdEncoding.DecodeString(signatureText)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signatureTextBytes)
	if err != nil {
		return false, err
	} else {
		return true, err
	}
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
