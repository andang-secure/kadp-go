package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andang-security/kadp-go/algorithm"
	"github.com/andang-security/kadp-go/mode"
	"github.com/andang-security/kadp-go/padding"
	"github.com/andang-security/kadp-go/utils"
	"github.com/go-irain/logger"
	"github.com/zalando/go-keyring"
	"log"
	"regexp"
	"runtime"
)

type KadpClient struct {
	domain          string
	credential      string
	version         string
	labelCipherText map[string]string
}

var keyPair = make(map[string]string)

var tokenMap = make(map[string]string)

func NewKADPClient(domain, credential string) *KadpClient {

	KADPClient := &KadpClient{
		domain:          domain,
		credential:      credential,
		labelCipherText: make(map[string]string),
	}
	log.Println("准备进行连接:", domain, credential)
	KADPClient.init()

	return KADPClient
}

func (client *KadpClient) init() {
	publicKey, privateKey, _ := rsaKeyGenerator()
	keyPair["publicKey"] = publicKey
	keyPair["privateKey"] = privateKey
	base64PublicKey, err := ExtractBase64FromPEM(publicKey)
	if err != nil {
		fmt.Println(err.Error())
	}

	mac := utils.GetMac()

	system, err := utils.GetOsInfo()
	if err != nil {
		logger.Error("获取系统失败")
	}
	ip, _ := utils.GetOutBoundIP()
	logger.Debug("获取mac:", mac)
	logger.Debug("获取os:", system)
	logger.Debug("获取ip", ip)

	decrypt, err := client.keyDecrypt(client.credential, []byte("XIANANDANGGONGSI"))
	logger.Debug("准备进行token解析:", decrypt)

	if err != nil {
		logger.Error("Failed to decrypt:", err)
		return
	}

	reqMap := map[string]string{
		"mac_addr": mac,
		"pub":      base64PublicKey,
		"system":   system,
		"ip":       ip,
	}

	credentialMap := map[string]string{
		"token": decrypt,
	}

	logger.Debug("开始连接:", reqMap)

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/auth", credentialMap, reqMap)

	var resultMap map[string]interface{}
	if result == nil {
		logger.Error("认证连接失败，请检查地址")
	}

	resultMap = result.(map[string]interface{})
	tokenMap["token"] = resultMap["data"].(string)

	if err != nil {
		logger.Error("Failed to send request:", err)
	}
	logger.Debug("连接结果：", result)

}

func (client *KadpClient) getDekCipherText(label string, length int) {

	reqMap := map[string]interface{}{
		"label":  label,
		"length": length,
	}
	logger.Debug("正在获取kek，发送token：", tokenMap)

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek_text", tokenMap, reqMap)

	logger.Debug("kek获取结果：", result)
	var resultMap map[string]interface{}
	resultMap = result.(map[string]interface{})
	code := resultMap["code"].(float64)

	if code == 4604 {
		client.init()
		result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek_text", tokenMap, reqMap)
		if err != nil {
			logger.Error("", err)
		}
		resultMap = result.(map[string]interface{})
	}
	data := resultMap["data"].(string)

	privateKey := keyPair["privateKey"]
	dekText, err := rsaDecryptWithPrivateKey(privateKey, data)
	if err != nil {
		fmt.Println(err)
	}
	logger.Debug("使用RSA进行解析：", dekText)

	if err != nil {
		logger.Error("Failed to send request:", err)
	}

	var TextJson map[string]string
	err = json.Unmarshal([]byte(dekText), &TextJson)
	if err != nil {
		logger.Error("解析 JSON 失败:", err)
		return
	}

	versionValue := TextJson["version"]

	client.labelCipherText[label] = dekText
	logger.Debug("kekMap：", client.labelCipherText)
	client.version = versionValue
	client.cipherTextDecrypt(label)

}

func (client *KadpClient) cipherTextDecrypt(label string) string {
	logger.Debug("准备解密dek")
	dekCipherReq := client.labelCipherText[label]

	var TextJson map[string]string
	err := json.Unmarshal([]byte(dekCipherReq), &TextJson)
	if err != nil {
		logger.Error("解析 JSON 失败:", err)
	}

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek", tokenMap, TextJson)
	if err != nil {
		logger.Error("请求dek解密失败", err)
	}
	logger.Debug("获取结果：", result)
	var resultMap map[string]interface{}
	resultMap = result.(map[string]interface{})
	code := resultMap["code"].(float64)
	if code == 4604 {
		client.init()
		result, err = utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek", tokenMap, dekCipherReq)
		if err != nil {
			logger.Error("请求失败", err)
		}
		resultMap = result.(map[string]interface{})
	}
	dek := resultMap["data"].(string)
	privateKey := keyPair["privateKey"]
	dekKeyBase, err := rsaDecryptWithPrivateKey(privateKey, dek)
	if err != nil {
		logger.Error(err)
	}
	logger.Debug("dek明文获取,Base64编码：" + dekKeyBase)

	goos := runtime.GOOS
	if goos == "linux" {
		keyring.MockInit()
	}
	err = keyring.Set("kadp", label, dekKeyBase)
	if err != nil {
		return ""
	}

	return dekKeyBase

}

func (client *KadpClient) getKey(length int, label string) (string, error) {

	if length != 16 && length != 32 && length != 24 {
		return "", errors.New("length parameter error, can only be 16-24-32")
	}

	key, err := keyring.Get("kadp", label)
	if err != nil {
		logger.Error(err)
	}
	logger.Debug("getkey," + key)

	if key == "" {
		logger.Debug("正在获取key")
		if client.labelCipherText[label] == "" {
			client.getDekCipherText(label, length)
		} else {
			client.cipherTextDecrypt(label)
		}
		key, _ = keyring.Get("kadp", label)

	}

	return key, nil
}

func (client *KadpClient) keyDecrypt(ciphertext string, key []byte) (string, error) {

	decodeCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	// 这里示例简化，将IV设置为密钥
	copy(iv, key)

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, decodeCiphertext)

	// 去除填充数据
	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]

	// 创建正则表达式模式，匹配非可见字符和特殊字符
	pattern := "[[:cntrl:]]"

	// 使用正则表达式替换乱码部分
	re := regexp.MustCompile(pattern)
	trimmedToken := re.ReplaceAllString(string(plaintext), "")

	return trimmedToken, nil
}

func (client *KadpClient) FpeEncipher(plaintext string, fpe algorithm.Fpe, tweak string, radix, length int, label string, start, end int) (string, error) {

	key, err := client.getKey(length, label)
	logger.Debug("获取到key：", key)
	if err != nil {
		return "", err
	}

	var ciphertext string
	switch fpe {
	case algorithm.FF1:
		ciphertext, err = ff1Encrypt(plaintext, key, tweak, radix, start, end)
	case algorithm.FF3:
		ciphertext, err = ff3Encrypt(plaintext, key, tweak, radix, start, end)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) FpeDecipher(ciphertext string, fpe algorithm.Fpe, tweak string, radix, length int, label string, start, end int) (string, error) {
	logger.Debug("正在解密")
	key, err := client.getKey(length, label)
	logger.Debug("获取到key", key)
	if err != nil {
		return key, err
	}
	var plaintext string
	switch fpe {
	case algorithm.FF1:
		plaintext, err = ff1Decrypt(ciphertext, key, tweak, radix, start, end)
	case algorithm.FF3:
		plaintext, err = ff3Decrypt(ciphertext, key, tweak, radix, start, end)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return plaintext, err
}

func (client *KadpClient) Encipher(plaintext []byte, design algorithm.Symmetry, modeVal mode.Mode, paddingVal padding.Padding, length int, label, iv string) (string, error) {

	key, err := client.getKey(length, label)
	logger.Debug("获取到key：", key)
	if err != nil {
		return "", err
	}

	var ciphertext string
	switch design {
	case algorithm.AES:
		if modeVal == mode.CBC {
			if paddingVal == padding.PKCS5Padding {
				ciphertext, err = aseCbcPKCS5Encrypt(plaintext, []byte(key), []byte(iv))
			} else {
				ciphertext, err = aseCbcNoPadEncrypt(plaintext, []byte(key), []byte(iv))
			}

		}
	case algorithm.SM4:
		logger.Debug("开始进行SM4加密")
		ciphertext, err = sm4CbcEncrypt(plaintext, key)

	case algorithm.DES:
		ciphertext, err = tripleDesEncrypt(plaintext, []byte(key), []byte(iv))
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) Decipher(ciphertext string, design algorithm.Symmetry, modeVal mode.Mode, paddingVal padding.Padding, length int, label, iv string) (string, error) {

	key, err := client.getKey(length, label)
	logger.Debug("获取到key：", key)
	if err != nil {
		return "", err
	}

	var plaintext string
	switch design {
	case algorithm.AES:

		if modeVal == mode.CBC {
			if paddingVal == padding.PKCS5Padding {
				plaintext, err = aseCbcPKCS5Decrypt(ciphertext, []byte(key), []byte(iv))
			} else {
				plaintext, err = aseCbcNoPadDecrypt(ciphertext, []byte(key), []byte(iv))
			}

		}
	case algorithm.SM4:

		plaintext, err = sm4CbcDecrypt(ciphertext, key)
	case algorithm.DES:
		ciphertext, err = tripleDesDecrypt(ciphertext, []byte(key), []byte(iv))
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return plaintext, err
}

func (client *KadpClient) AsymmetricKeyPair(design algorithm.Asymmetric) (publicKey string, privateKey string, err error) {
	var pub string
	var pri string
	var errs error

	switch design {
	case algorithm.RSA:
		pub, pri, errs = rsaKeyGenerator()
		if err != nil {
			return "", "", errs
		}
	case algorithm.SM2:
		pub, pri, errs = sm2GenerateKey()
		if err != nil {
			return "", "", errs
		}
	}

	return pub, pri, nil
}

func (client *KadpClient) AsymmetricPubEncrypt(plaintext string, design algorithm.Asymmetric, publicKey string) (string, error) {

	var ciphertext string
	var err error
	switch design {
	case algorithm.RSA:
		ciphertext, err = rsaEncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			return "", err
		}
	case algorithm.SM2:
		ciphertext, err = sm2PubEncrypt(publicKey, plaintext)
		if err != nil {
			return "", err
		}
	}

	return ciphertext, nil
}

func (client *KadpClient) AsymmetricPriDecrypt(ciphertext string, design algorithm.Asymmetric, privateKey string) (string, error) {

	var plaintext string
	var err error
	switch design {
	case algorithm.RSA:
		plaintext, err = rsaDecryptWithPrivateKey(privateKey, ciphertext)
		if err != nil {
			return "", err
		}
	case algorithm.SM2:
		plaintext, err = sm2PriDecrypt(privateKey, ciphertext)
		if err != nil {
			return "", err
		}
	}

	return plaintext, nil
}

func (client *KadpClient) SM2Signature(plaintext, privateKey string, uid []byte) (r, s string, err error) {

	r, s, errs := sm2Sign(privateKey, []byte(plaintext), uid)
	if errs != nil {
		return "", "", errs
	}

	return r, s, nil
}

func (client *KadpClient) SM2Verify(plaintext, publicKey, r, s string, uid []byte) (bool, error) {

	VerifyBool, err := sm2Verify(publicKey, []byte(plaintext), uid, r, s)
	if err != nil {
		return VerifyBool, err
	}

	return VerifyBool, nil
}

func (client *KadpClient) RsaSignature(plaintext, privateKey string) (string, error) {

	sign, err := rsaSign(privateKey, []byte(plaintext))
	if err != nil {
		return "", err
	}

	return sign, nil
}

func (client *KadpClient) RsaVerify(plaintext, SignatureText, publicKey string) (bool, error) {

	VerifyBool, err := rsaVerify(publicKey, SignatureText, []byte(plaintext))
	if err != nil {
		return VerifyBool, err
	}

	return VerifyBool, nil
}

func (client *KadpClient) DigestEncrypt(plaintext string) string {

	cipherText := sm3Encrypt([]byte(plaintext))

	return cipherText
}
