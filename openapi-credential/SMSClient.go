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
	//domain           string
	//credential       string
	//clientCredential string
	//version          string
	labelCipherText map[string]string
	keyMap          map[string]string
	//keyStore         keystore.KeyStore
	//keyStoreFileName string
	//keyStorePassWord string
	authStatus bool
	//sessionKey       []byte
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
}

var keyPair1 = make(map[string]string)

var tokenMap1 = make(map[string]string)

// NewSMSClient 初始化SMS
func NewSMSClient(domain, appKey, appSecret, keyStoreFileName, keyStorePassWord string) (*SMSClient, error) {
	//logger.DailyLogger(logFileDir, logFileName)

	SMSClient := &SMSClient{
		appKey:           appKey,
		appSecret:        appSecret,
		domain:           domain,
		keyStoreFileName: keyStoreFileName,
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
			return nil, err
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
		return false, err
	}
	if loginResp.Code != 0 {
		fmt.Errorf("客户端认证失败，请重试", loginResp.Code, loginResp.Msg)
		return false, fmt.Errorf("客户端认证失败，请重试")
	}

	tokenMap1["token"] = loginResp.Data["token"]
	//2.解析token文件
	user, err := utils.ParseToken(tokenMap1["token"])
	if err != nil {
		log.Println("解析token文件失败", err)
		return false, err
	}
	fmt.Println("------------", user.KeyStorePwd)
	//client.keyStorePassWord = user.KeyStorePwd
	client.keyStorePassWord = "shanghaiandanggongsi"
	user.KeyStorePwd = "shanghaiandanggongsi"
	//3.认证通过开始创建keystore文件
	ks := utils.ReadKeyStore(client.keyStoreFileName, []byte(user.KeyStorePwd))

	//4.生成公私钥对
	pub, pri, errs := rsaKeyGenerator()
	if errs != nil {
		return false, errs
	}
	//5. 存储keystore文件
	keyEntryPri := utils.CreateKeyEntry([]byte(pri))
	keyEntryPub := utils.CreateKeyEntry([]byte(pub))
	utils.StoreSecretKeySMS("pri", keyEntryPri, ks, client.keyStoreFileName, []byte(user.KeyStorePwd))
	if err != nil {
		return false, err
	}
	utils.StoreSecretKeySMS("pub", keyEntryPub, ks, client.keyStoreFileName, []byte(user.KeyStorePwd))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (client *SMSClient) GetSmsCipherText(label string) (string, error) {
	ks := utils.ReadKeyStore(client.keyStoreFileName, []byte(client.keyStorePassWord))
	//1.先从keystore中获取私钥和公钥
	pri, err := ks.GetPrivateKeyEntry("pri", []byte(client.keyStorePassWord))
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	log.Printf("%#v", string(pri.PrivateKey))
	pub, err := ks.GetPrivateKeyEntry("pub", []byte(client.keyStorePassWord))
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	log.Printf("%#v", string(pub.PrivateKey))
	// 去除头尾
	//publicKey := strings.TrimSpace(string(pub.PrivateKey))
	//cleanedKey := strings.TrimPrefix(strings.TrimSuffix(publicKey, "-----END PUBLIC KEY-----"), "-----BEGIN PUBLIC KEY-----")
	//fmt.Println(cleanedKey)
	//base64.StdEncoding.EncodeToString(pub.PrivateKey)
	//2.组织参数
	/*
		{
			request_ := utils.NewRequest()
			request_.Protocol = util.DefaultString(client.Protocol, protocol)
			request_.Method = method
			request_.Pathname = tea.String("/")
			request_.Headers = tea.Merge(requestHeaders)
			request_.Headers["accept"] = tea.String("application/x-protobuf")
			request_.Headers["host"] = client.Endpoint
			request_.Headers["date"] = util.GetDateUTCString()
			request_.Headers["user-agent"] = client.UserAgent
			request_.Headers["x-kms-apiversion"] = apiVersion
			request_.Headers["x-kms-apiname"] = apiName
			request_.Headers["x-kms-signaturemethod"] = signatureMethod
			request_.Headers["x-kms-acccesskeyid"] = client.Credential.GetAccessKeyId()
			request_.Headers["content-type"] = tea.String("application/x-protobuf")
			request_.Headers["content-length"], _err = dedicatedkmsopenapiutil.GetContentLength(reqBodyBytes)
			if _err != nil {
				return _result, _err
			}

			request_.Headers["content-sha256"] = string_.ToUpper(openapiutil.HexEncode(openapiutil.Hash(reqBodyBytes, tea.String("ACS3-RSA-SHA256"))))
			request_.Body = tea.ToReader(reqBodyBytes)
			strToSign, _err := dedicatedkmsopenapiutil.GetStringToSign(method, request_.Pathname, request_.Headers, request_.Query)
			if _err != nil {
				return _result, _err
			}
		}
	*/

	//3.私钥签名参数
	rsaSign(string(pri.PrivateKey), []byte(""))

	//4.发送请求

	if label == "" || len(pub.PrivateKey) == 0 {
		return "", err
	}
	reqMap := map[string]string{
		"label": label,
		"pub":   base64.StdEncoding.EncodeToString(pub.PrivateKey),
		//"pub": cleanedKey,
	}
	credentialMap := map[string]string{
		"token": tokenMap1["token"],
	}

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/credential/cipher", credentialMap, reqMap)
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
		fmt.Errorf("客户端获取密文失败，请重试")
		return "", fmt.Errorf("客户端获取密文失败，请重试")
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
