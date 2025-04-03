package kadp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andang-secure/kadp-go/global"
	"github.com/andang-secure/kadp-go/utils"
	logger "github.com/sirupsen/logrus"
	"log"
	"strconv"
)

type SMSClient struct {
	labelCipherText map[string]string
	keyMap          map[string]string
	//keyStore         keystore.KeyStore
	authStatus bool
	//认证所需参数
	appKey           string
	appSecret        string
	label            string
	pub              string
	version          string
	keyStoreFileName string
	domain           string //域名
	keyStorePassWord string
	authToken        string
	registerToken    string
}

var keyPair1 = make(map[string]string)

var tokenMap1 = make(map[string]string)

// NewSMSClient 初始化SMS
func NewSMSClient(domain, appKey, appSecret, keyStoreFileName, keyStorePassWord, registerToken string) (*SMSClient, error) {
	//logger.DailyLogger(logFileDir, logFileName)

	SMSClient := &SMSClient{
		appKey:           appKey,
		appSecret:        appSecret,
		domain:           domain,
		keyStoreFileName: keyStoreFileName,
		registerToken:    registerToken,
		//keyStore: utils.ReadKeyStore(keyStoreFileName, []byte(keyStorePassWord)),
		//version:          "1.0",
		//label:            "",
		//pub:              "",
	}
	var err error
	SMSClient.labelCipherText = make(map[string]string, 0)
	SMSClient.keyMap = make(map[string]string, 0)
	SMSClient.authStatus, err = SMSClient.init()
	if err != nil {
		return nil, err
	}

	return SMSClient, nil
}

func (client *SMSClient) authClient(addr, system, ip string) (interface{}, error) {
	if addr != "" && system != "" && ip != "" {

		/*
			//先进行注册令牌验证
			reqMap1 := map[string]string{
				"mac_addr": addr,
				"ip":       ip,
				"system":   system,
				"token":    client.registerToken,
			}
			resultToken, err := utils.AuthSendRequest("POST", client.domain+"/v1/ksp/open_api/kadp/register", reqMap1)
			if err != nil {
				return nil, err
			}
			resultMap := resultToken.(map[string]interface{})
			fmt.Println(resultMap)
			if resultMap["code"].(float64) != 0 {
				fmt.Errorf("客户端注册令牌无效，请重试")
				return false, fmt.Errorf("客户端注册令牌无效，请重试")
			}
		*/
		//2.开始登录
		reqMap := map[string]string{
			"mac_addr":  addr,
			"ip":        ip,
			"system":    system,
			"appid":     client.appKey,
			"appsecret": client.appSecret,
			"domain":    strconv.Itoa(1),
		}
		result, err := utils.AuthSendRequest("POST", client.domain+"/v1/ksp/open_api/login", reqMap)
		if err != nil {
			return nil, errors.New("认证客户端错误")
		}
		return result, nil
	}
	return nil, errors.New("认证客户端错误")
}

// init 开始加载进行连接
func (client *SMSClient) init() (bool, error) {

	mac, err := utils.GetMac()
	if err != nil {
		return false, fmt.Errorf("获取系统失败: %v", err)
	}

	system, err := utils.GetOsInfo()
	if err != nil {
		logger.Error("获取系统失败")
		return false, fmt.Errorf("获取系统失败: %v", err)
	}

	ip, err := utils.GetOutBoundIP()
	if err != nil {
		logger.Error("获取系统失败")
		return false, fmt.Errorf("获取系统失败: %v", err)
	}

	//1.开始认证
	isAuthResult, err := client.authClient(mac, ip, system)
	var loginResp = global.AuthResponse{}
	resultByte, err := json.Marshal(isAuthResult)

	err = json.Unmarshal(resultByte, &loginResp)
	if err != nil {
		log.Println("反序列化失败")
		return false, fmt.Errorf("反序列化失败")
	}
	if loginResp.Code != 0 {
		fmt.Errorf("客户端认证失败，请重试%d:%s", loginResp.Code, loginResp.Msg)
		return false, fmt.Errorf("客户端认证失败，请重试")
	}

	tokenMap1["token"] = loginResp.Data["token"]
	//2.解析token文件
	user, err := utils.ParseToken(tokenMap1["token"])
	if err != nil {
		log.Println("解析token文件失败", err)
		return false, fmt.Errorf("解析token文件失败，请重试")
	}

	client.keyStorePassWord = user.KeyStorePwd
	//3.认证通过开始创建keystore文件
	ks := utils.ReadKeyStore(client.keyStoreFileName, []byte(client.keyStorePassWord))

	//4.生成公私钥对
	pub, pri, errs := rsaKeyGenerator()
	if errs != nil {
		_ = fmt.Errorf("生成密钥对失败%s", errs.Error())
		return false, fmt.Errorf("生成密钥对失败")
	}
	//5. 存储keystore文件
	keyEntryPri := utils.CreateKeyEntry([]byte(pri))
	keyEntryPub := utils.CreateKeyEntry([]byte(pub))
	utils.StoreSecretKeySMS("pri", keyEntryPri, ks, client.keyStoreFileName, []byte(client.keyStorePassWord))
	if err != nil {
		_ = fmt.Errorf("StoreSecretKeySMS-err%s", err.Error())
		return false, fmt.Errorf("SDK错误")
	}
	utils.StoreSecretKeySMS("pub", keyEntryPub, ks, client.keyStoreFileName, []byte(client.keyStorePassWord))
	if err != nil {
		_ = fmt.Errorf("StoreSecretKeySMS-err%s", err.Error())
		return false, fmt.Errorf("SDK错误")
	}
	return true, nil
}

func (client *SMSClient) GetSmsCipherText(label string) (string, error) {
	ks := utils.ReadKeyStore(client.keyStoreFileName, []byte(client.keyStorePassWord))
	//1.先从keystore中获取私钥和公钥
	pri, err := ks.GetPrivateKeyEntry("pri", []byte(client.keyStorePassWord))
	if err != nil {
		log.Print(err)
		return "", errors.New("sdk-获取私钥失败")
	}
	//log.Printf("%#v", string(pri.PrivateKey))
	pub, err := ks.GetPrivateKeyEntry("pub", []byte(client.keyStorePassWord))
	if err != nil {
		log.Print(err)
		return "", errors.New("sdk-获取公钥失败")
	}

	//4.发送请求
	if label == "" || len(pub.PrivateKey) == 0 {
		return "", err
	}
	reqMap := map[string]string{
		"label":   label,
		"version": "",
		"pub":     base64.StdEncoding.EncodeToString(pub.PrivateKey),
	}
	credentialMap := map[string]string{
		"token": tokenMap1["token"],
	}

	//result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/credential/cipher", credentialMap, reqMap)
	result, err := utils.SendSdkAuthRequest("POST", client.domain+"/v1/ksp/open_api/credential/cipher", credentialMap, reqMap, base64.StdEncoding.EncodeToString(pri.PrivateKey), base64.StdEncoding.EncodeToString(pub.PrivateKey))
	if err != nil {
		logger.Error("Failed to send request:", err)
		return "", errors.New("failed to send request")
	}

	resultMap := result.(map[string]interface{})
	code := resultMap["code"].(float64)
	if code == 4604 {
		client.authStatus, err = client.init()
		if err != nil {
			return "", err
		}
		result, err = utils.SendRequest("GET", client.domain+"/v1/ksp/open_api/credential/cipher", credentialMap, reqMap)
		if err != nil {
			logger.Error("请求失败", err)
			return "", err
		}
		resultMap = result.(map[string]interface{})
	}
	//5.解析响应
	var getCipherResp = global.AuthResponse{}
	resultByte, err := json.Marshal(result)
	if err != nil {
		logger.Error("反序列化失败", err)
		return "", err
	}
	err = json.Unmarshal(resultByte, &getCipherResp)
	if err != nil {
		log.Println("反序列化失败")
		return "", err
	}
	if getCipherResp.Code != 0 {
		fmt.Errorf("客户端获取密文失败，请重试%d", getCipherResp.Code)
		return "", fmt.Errorf("客户端获取密文失败，请重试.%s", getCipherResp.Msg)
	}
	cipherText := getCipherResp.Data["ciphertext"]
	cipherKey := getCipherResp.Data["cipher_key"]

	//6.私钥解密凭据加密密钥
	plainKey, err := rsaDecryptWithPrivateKey(string(pri.PrivateKey), cipherKey)
	if err != nil {
		return "", err
	}

	//7.凭据加密密钥解密凭据
	sms, err := aseCbcPaddingDecrypt(cipherText, base64.StdEncoding.EncodeToString([]byte(plainKey)), []byte(plainKey), PKCS7Padding, "AES")
	if err != nil {
		return "", err
	}

	return sms, nil
}
