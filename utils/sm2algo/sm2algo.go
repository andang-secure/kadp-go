package sm2algo

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

func EncryptBySm2(publicKeyBlob string, origData []byte) ([]byte, error) {
	pub, err := x509.ReadPublicKeyFromPem([]byte(publicKeyBlob))
	if err != nil {
		return nil, err
	}
	return pub.EncryptAsn1(origData, rand.Reader)
}

func EncryptBySm2SRC(publicKeyBlob string, origData []byte) ([]byte, error) {
	pub, err := getPublicKeySm2(publicKeyBlob)
	if err != nil {
		return nil, err
	}
	return pub.EncryptAsn1(origData, rand.Reader)
}

func DecryptBySm2(privateKeyBlob string, origData []byte) ([]byte, error) {
	pri, err := x509.ReadPrivateKeyFromPem([]byte(privateKeyBlob), nil)
	if err != nil {
		return nil, err
	}
	return pri.DecryptAsn1(origData)
}

func DecryptBySm2SRC(privateKeyBlob string, origData []byte) ([]byte, error) {
	pri, err := getPrivateKeySm2(privateKeyBlob)
	if err != nil {
		return nil, err
	}

	return pri.DecryptAsn1(origData)
}

func Encrypt(publicKeyBlob string, origData []byte) ([]byte, error) {
	pub, err := getPublicKey(publicKeyBlob)
	if err != nil {
		return nil, err
	}
	return pub.EncryptAsn1(origData, rand.Reader)
}

func EncryptToString(publicKeyBlob string, origData []byte) (string, error) {
	data, err := Encrypt(publicKeyBlob, origData)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// 解析公钥-不带头尾
func getPublicKey(publicKeyBlob string) (*sm2.PublicKey, error) {
	publicKey := []byte(
		`-----BEGIN PUBLIC KEY-----
		` + publicKeyBlob +
			`-----END PUBLIC KEY-----
`)
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	return x509.ParseSm2PublicKey(block.Bytes)
}

// 公钥带头尾的字符串处理
func getPublicKeySm2(publicKeyBlob string) (*sm2.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyBlob))
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	return x509.ParseSm2PublicKey(block.Bytes)
}

func getPrivateKeySm2(privateKeyBlob string) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyBlob))
	if block == nil {
		fmt.Println("解码失败")
		return nil, errors.New("public key error")
	}
	// 解析私钥钥
	//return x509.ParseSm2PrivateKey(block.Bytes)
	return x509.ParsePKCS8PrivateKey(block.Bytes, nil)
}

func SignWithSm2(data string, privateKey string) (string, error) {
	pri, err := getPrivateKeySm2(privateKey)

	if err != nil {
		fmt.Println("sm2私钥解码失败")
		return "", err
	}

	signData, err := pri.Sign(rand.Reader, []byte(data), nil)
	if err != nil {
		logger.Info("sm2签名失败")
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signData), nil
}

func VerifySignWithSm2(msgData string, signData string, pubKey string) (bool, error) {
	pub, err := getPublicKeySm2(pubKey)
	if err != nil {
		logger.Info("sm2公钥解码失败")
		return false, err
	}
	signByte, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		logger.Info("sm2签名数据解码失败")
		return false, err
	}
	bl := pub.Verify([]byte(msgData), signByte)
	if bl {
		return true, nil
	}
	return false, nil
}

func ParseSmCertificate(certStr string) *sm2.PublicKey {
	blockCa, _ := pem.Decode([]byte(certStr))
	caCert, err := x509.ParseCertificate(blockCa.Bytes)
	if err != nil {
		fmt.Println("=======33", err)
	}
	v := caCert.PublicKey.(*ecdsa.PublicKey)
	pub := sm2.PublicKey{
		Curve: v.Curve,
		X:     v.X,
		Y:     v.Y,
	}
	return &pub
}

func VerifySignWithSm2NoPub(msgData string, signData string, pub *sm2.PublicKey) (bool, error) {
	signByte, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		logger.Info("sm2签名数据解码失败")
		return false, err
	}
	bl := pub.Verify([]byte(msgData), signByte)
	if bl {
		return true, nil
	}
	return false, nil
}
