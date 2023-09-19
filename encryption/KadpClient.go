package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andang-security/kadp/encryption/rsa"
	"github.com/andang-security/kadp/utils"
	"log"
	"regexp"
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
	log.Println(domain, credential)
	KADPClient.init()

	return KADPClient
}

func (client *KadpClient) init() {
	publicKey, privateKey := rsa.KeyGenerator()
	keyPair["publicKey"] = publicKey
	keyPair["privateKey"] = privateKey
	base64PublicKey, err := rsa.ExtractBase64FromPEM(publicKey)
	if err != nil {
		fmt.Println(err.Error())
	}

	mac := utils.GetMac()
	system := utils.GetOsInfo()
	ip := "192.168.0.122"

	decrypt, err := client.decrypt(client.credential, []byte("XIANANDANGGONGSI"))
	log.Println("解密：" + decrypt)
	if err != nil {
		log.Println("Failed to decrypt:", err)
		return
	}

	reqMap := map[string]string{
		"mac_addr": mac,
		"pub":      base64PublicKey,
		"system":   system,
		"ip":       ip,
	}

	fmt.Println("发送请求", reqMap)

	credentialMap := map[string]string{
		"token": decrypt,
	}

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/auth", credentialMap, reqMap)

	var resultMap map[string]interface{}
	resultMap = result.(map[string]interface{})
	tokenMap["token"] = resultMap["data"].(string)

	if err != nil {
		log.Println("Failed to send request:", err)
	}
	log.Println("结果", result)

}

func (client *KadpClient) GetDekCipherText(label string, length int) {

	reqMap := map[string]interface{}{
		"label":  label,
		"length": length,
	}
	log.Println("发送token：", tokenMap)

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek_text", tokenMap, reqMap)

	log.Println("获取结果：", result)
	var resultMap map[string]interface{}
	resultMap = result.(map[string]interface{})
	code := resultMap["code"].(float64)

	if code == 4604 {
		client.init()
		result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek_text", tokenMap, reqMap)
		if err != nil {
			fmt.Println("", err)
		}
		resultMap = result.(map[string]interface{})
	}
	data := resultMap["data"].(string)

	privateKey := keyPair["privateKey"]
	fmt.Println("取出" + privateKey)
	dekText, err := rsa.DecryptWithPrivateKey(privateKey, data)
	if err != nil {
		fmt.Println(err)
	}
	log.Println("解密出", dekText)

	if err != nil {
		log.Println("Failed to send request:", err)
	}

	var TextJson map[string]string
	err = json.Unmarshal([]byte(dekText), &TextJson)
	if err != nil {
		fmt.Println("解析 JSON 失败:", err)
		return
	}

	versionValue := TextJson["version"]

	client.labelCipherText[label] = dekText
	log.Println("存入dek", client.labelCipherText)
	client.version = versionValue
	client.cipherTextDecrypt(label)

}

func (client *KadpClient) cipherTextDecrypt(label string) string {
	dekCipherReq := client.labelCipherText[label]
	fmt.Println("准备发送", label+dekCipherReq)
	fmt.Println("token发送", tokenMap)

	var TextJson map[string]string
	err := json.Unmarshal([]byte(dekCipherReq), &TextJson)
	if err != nil {
		fmt.Println(err)
	}

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek", tokenMap, TextJson)
	if err != nil {
		fmt.Println(err)
	}
	log.Println("获取结果：", result)
	var resultMap map[string]interface{}
	resultMap = result.(map[string]interface{})
	code := resultMap["code"].(float64)
	if code == 4604 {
		client.init()
		result, err = utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek", tokenMap, dekCipherReq)
		if err != nil {
			fmt.Println("", err)
		}
		resultMap = result.(map[string]interface{})
	}
	dek := resultMap["data"].(string)
	privateKey := keyPair["privateKey"]
	dekKeyBase, err := rsa.DecryptWithPrivateKey(privateKey, dek)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(dekKeyBase)

	return dekKeyBase

}

func (client *KadpClient) getKey(length int, label string) (string, error) {
	if length != 16 && length != 32 && length != 24 {
		return "", errors.New("length parameter error, can only be 16-24-32")
	}
	if client.labelCipherText[label] == "" {
		client.GetDekCipherText(label, length)
	}
	return client.cipherTextDecrypt(label), nil
}

func (client *KadpClient) decrypt(ciphertext string, key []byte) (string, error) {

	decodeCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)

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

func (client *KadpClient) FpeEncipher(plaintext string, fpe Fpe, radix, length int, label string) (string, error) {

	key, err := client.getKey(length, label)
	if err != nil {
		return key, err
	}

	var ciphertext string
	switch fpe {
	case FF1:
		ciphertext, _ = ff1Encrypt(plaintext, key, radix)
	case FF3:
		fmt.Println("Value2 selected")
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) FpeDecipher(ciphertext string, fpe Fpe, radix, length int, label string) (string, error) {

	key, err := client.getKey(length, label)
	if err != nil {
		return key, err
	}
	var plaintext string
	switch fpe {
	case FF1:
		plaintext, err = ff1Decrypt(ciphertext, key, radix)
	case FF3:
		plaintext, err = ff3encrypt(ciphertext, key, radix)
	default:
		fmt.Println("Invalid value")
	}
	if err != nil {
		return "", err
	}

	return plaintext, err
}
