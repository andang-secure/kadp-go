package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/andang-secure/kadp-go/utils/sm2algo"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
	"log"
)

var random []byte

const (
	severCrt  = "C:\\Users\\13299\\go\\src\\kadp\\utils\\session\\server_sign.crt"
	severKey  = "C:\\Users\\13299\\go\\src\\kadp\\utils\\session\\server_sign.key"
	clientCrt = "C:\\Users\\13299\\go\\src\\kadp\\utils\\session\\client_sign.crt"
	clientKey = "C:\\Users\\13299\\go\\src\\kadp\\utils\\session\\client_sign.key"
)

func CreateRomdomPub() (sign, Pub string, err error) {

	//2.找不见就创建 生成随机数
	random, err = GenerateRandom()
	if err != nil {
		log.Println("解析密钥创建PDU错误," + err.Error())
		return
	}

	certData, err := ioutil.ReadFile(clientCrt)

	// 解码PEM格式的证书

	//3.证书中提取对方s公钥加密随机数 切换服务端的证书来解析公钥

	pub := ParseSmCertificate(certData)

	//fmt.Println("加密前：", random)
	pubRandom, err := pub.EncryptAsn1(random, rand.Reader)
	if err != nil {
		log.Println("密管加密随机数失败：=", err)
		return "", "", err

	}

	//signRandom, err := sm2algo.SignWithSm2(hex.EncodeToString(random), ClientKey)
	ClientKey, err := ioutil.ReadFile(clientKey)

	signRandom, err := sm2algo.SignWithSm2(string(random), string(ClientKey))

	if err != nil {
		fmt.Println("签名失败", err)

		return "", "", err
	}

	PubRandom := base64.StdEncoding.EncodeToString(pubRandom)

	return signRandom, PubRandom, nil
}

func SessionKeyResp(PubRandomR string, SignRandomR, MyRandomData string) (key []byte, err error) {

	originData, err := base64.StdEncoding.DecodeString(PubRandomR)
	if err != nil {
		log.Println("base64解码加密数据失败", err)
		return nil, err
	}
	SeverKey, err := ioutil.ReadFile(severKey)

	randomDataR, err := sm2algo.DecryptBySm2SRC(string(SeverKey), originData)
	if err != nil {
		log.Println("解密加密机随机数数据失败", err)
		return nil, err
	}

	ServeCert, err := ioutil.ReadFile(severCrt)

	pub := sm2algo.ParseSmCertificate(string(ServeCert))

	flag, err := sm2algo.VerifySignWithSm2NoPub(string(randomDataR), SignRandomR, pub)
	if err != nil {
		log.Println("------密管公钥验签失败", err)
		return nil, err
	}
	if !flag {
		log.Println("密管公钥验签,签名数据错误", err)
		return nil, errors.New("签名数据错误")
	}

	randomData, err := base64.StdEncoding.DecodeString(MyRandomData)
	if err != nil {
		return nil, err
	}

	isEqual := bytes.Equal(random, randomData[:32])
	if isEqual {
		log.Println("字节数组相等")
	} else {
		log.Println("字节数组不相等")
		return nil, errors.New("随机数错误")
	}

	//bodyByte, _ := base64.StdEncoding.DecodeString(string(body))
	//body1, err := Sm4CBCDecrypt(bodyByte, SessionKey[:16], SessionKey[16:], "PKCS5")

	//9.异或得到会话密钥
	sessionHsmKey := XorBytes(randomData, randomDataR)
	SessionKey := sessionHsmKey
	//fmt.Printf("----会话密钥：%x\n", SessionKey[:16])
	//fmt.Printf("----会话密钥iv：%x\n", SessionKey[16:])

	return SessionKey, nil
}

func ParseSmCertificate(certStr []byte) *sm2.PublicKey {
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
