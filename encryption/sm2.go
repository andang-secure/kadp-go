package encryption

import (
	"crypto/rand"
	"fmt"
	"github.com/go-irain/logger"
	"github.com/tjfoc/gmsm/x509"
	"log"
	"math/big"

	"encoding/base64"
	"encoding/pem"
	"github.com/tjfoc/gmsm/sm2"
)

func sm2GenerateKey() (string, string, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	publicKeyDER, err := x509.MarshalSm2PublicKey(&privateKey.PublicKey)
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
	privateKeyDER, err := x509.MarshalSm2PrivateKey(privateKey, nil)
	if err != nil {
		return "", "", err
	}
	// 创建私钥的PEM块
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	// 将私钥PEM块编码为字符串
	encodedPrivateKey := string(pem.EncodeToMemory(privateKeyBlock))

	return encodedPublicKey, encodedPrivateKey, nil
}

func sm2PubEncrypt(pubKey string, plaintext string) (string, error) {

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		logger.Error("解码PEM失败")
		return "", fmt.Errorf("解码PEM失败")
	}

	pub, err := x509.ParseSm2PublicKey(block.Bytes)

	ciphertext, err := sm2.EncryptAsn1(pub, []byte(plaintext), rand.Reader)
	if err != nil {
		return "", err
	}

	base64Ciphertext := base64.StdEncoding.EncodeToString(ciphertext)

	return base64Ciphertext, nil
}

func sm2PriDecrypt(priKey string, cipherText string) (string, error) {
	decodeData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode([]byte(priKey))
	if block == nil {
		logger.Error("解码PEM失败")
		return "", fmt.Errorf("解码PEM失败")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)

	if err != nil {
		return "", err
	}
	ciphertext, err := sm2.DecryptAsn1(parsedKey, decodeData)
	if err != nil {
		return "", err
	}

	return string(ciphertext), nil
}

func sm2Sign(pubKey string, data []byte, uid []byte) (r, s string, err error) {

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		log.Println("解码PEM失败")
		return "", "", fmt.Errorf("解码PEM失败")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)
	if err != nil {
		return "", "", err
	}
	sign, b, err := sm2.Sm2Sign(parsedKey, data, uid, rand.Reader)
	if err != nil {
		return "", "", err
	}
	signBytes := sign.Bytes()
	bBytes := b.Bytes()

	rBase64 := base64.StdEncoding.EncodeToString(signBytes)
	sBase64 := base64.StdEncoding.EncodeToString(bBytes)

	return rBase64, sBase64, nil
}

func sm2Verify(pubKey string, data []byte, uid []byte, r, s string) (bool, error) {

	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		logger.Error("解码PEM失败")
		return false, fmt.Errorf("解码PEM失败")
	}

	publicKeyObject, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	rBytes, err := base64.StdEncoding.DecodeString(r)
	if err != nil {
		return false, err
	}
	sBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false, err
	}

	rInt := new(big.Int).SetBytes(rBytes)

	sInt := new(big.Int).SetBytes(sBytes)

	isVerify := sm2.Sm2Verify(publicKeyObject, data, uid, rInt, sInt)

	return isVerify, nil
}
