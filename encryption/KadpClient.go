package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andang-security/kadp-go/algorithm"
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
	publicKey, privateKey := KeyGenerator()
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
	dekText, err := DecryptWithPrivateKey(privateKey, data)
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
	dekKeyBase, err := DecryptWithPrivateKey(privateKey, dek)
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

func (client *KadpClient) FpeEncipher(plaintext string, fpe algorithm.Fpe, radix, length int, label string) (string, error) {

	key, err := client.getKey(length, label)
	logger.Debug("获取到key：", key)
	if err != nil {
		return "", err
	}

	var ciphertext string
	switch fpe {
	case algorithm.FF1:
		ciphertext, err = ff1Encrypt(plaintext, key, radix)
	case algorithm.FF3:
		ciphertext, err = ff3Encrypt(plaintext, key, radix)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) FpeDecipher(ciphertext string, fpe algorithm.Fpe, radix, length int, label string) (string, error) {
	logger.Debug("正在解密")
	key, err := client.getKey(length, label)
	logger.Debug("获取到key", key)
	if err != nil {
		return key, err
	}
	var plaintext string
	switch fpe {
	case algorithm.FF1:
		plaintext, err = ff1Decrypt(ciphertext, key, radix)
	case algorithm.FF3:
		plaintext, err = ff3encrypt(ciphertext, key, radix)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return plaintext, err
}

func (client *KadpClient) Encipher(plaintext []byte, design algorithm.Symmetry, length int, label string) (string, error) {

	key, err := client.getKey(length, label)
	logger.Debug("获取到key：", key)
	if err != nil {
		return "", err
	}

	var ciphertext string
	switch design {
	case algorithm.AES:
		ciphertext, err = aesEncrypt(plaintext, []byte(key))
	//case algorithm.FF3:
	//	ciphertext, err = ff3Encrypt(plaintext, key, radix)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) Decipher(ciphertext string, design algorithm.Symmetry, length int, label string) (string, error) {

	key, err := client.getKey(length, label)
	logger.Debug("获取到key：", key)
	if err != nil {
		return "", err
	}

	var plaintext string
	switch design {
	case algorithm.AES:
		plaintext, err = aseDecrypt(ciphertext, []byte(key))
	//case algorithm.FF3:
	//	ciphertext, err = ff3Encrypt(plaintext, key, radix)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return plaintext, err
}
