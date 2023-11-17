package kadp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andang-secure/kadp-go/utils"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	logger "github.com/sirupsen/logrus"
	"regexp"
)

type KadpClient struct {
	domain           string
	credential       string
	clientCredential string
	version          string
	labelCipherText  map[string]string
	keyMap           map[string]string
	keyStore         keystore.KeyStore
	keyStoreFileName string
	keyStorePassWord string
	authStatus       bool
}

var keyPair = make(map[string]string)

var tokenMap = make(map[string]string)

// NewKADPClient 初始化KADP
func NewKADPClient(domain, credential, clientCredential, keyStoreFileName, keyStorePassWord string) (*KadpClient, error) {
	//logger.DailyLogger(logFileDir, logFileName)

	KADPClient := &KadpClient{
		domain:           domain,
		credential:       credential,
		clientCredential: clientCredential,
		keyStoreFileName: keyStoreFileName,
		keyStorePassWord: keyStorePassWord,
		keyStore:         utils.ReadKeyStore(keyStoreFileName, []byte(keyStorePassWord)),
	}
	var err error
	KADPClient.labelCipherText = make(map[string]string, 0)
	KADPClient.keyMap = make(map[string]string, 0)
	KADPClient.authStatus, err = KADPClient.init()
	if err != nil {
		return nil, err
	}

	return KADPClient, nil
}

func (client *KadpClient) authClient(addr, system, ip string) (interface{}, error) {
	if addr != "" && system != "" && ip != "" {
		reqMap := map[string]string{
			"mac_addr": addr,
			"ip":       ip,
			"system":   system,
			"token":    client.clientCredential,
		}
		result, err := utils.AuthSendRequest("POST", client.domain+"/v1/ksp/open_api/kadp/register", reqMap)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	return nil, nil
}

// init 开始加载进行连接
func (client *KadpClient) init() (bool, error) {
	publicKey, privateKey, err := rsaKeyGenerator()
	if err != nil {
		return false, fmt.Errorf("RSA生成密钥失败")
	}
	keyPair["publicKey"] = publicKey
	keyPair["privateKey"] = privateKey
	base64PublicKey, err := ExtractBase64FromPEM(publicKey)
	if err != nil {
		logger.Error(err.Error())
		return false, err
	}
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

	//开始认证

	isAuthResult, err := client.authClient(mac, ip, system)

	resultMap := isAuthResult.(map[string]interface{})
	if resultMap["code"].(float64) != 0 {
		fmt.Errorf("客户端认证失败，请重试")
		return false, fmt.Errorf("客户端认证失败，请重试")
	}

	//通过
	decrypt, err := client.keyDecrypt(client.credential, []byte("XIANANDANGGONGSI"))

	if err != nil {
		logger.Error("Failed to decrypt:", err)
		return false, err
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

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/auth", credentialMap, reqMap)

	if err != nil {
		logger.Error("Failed to send request:", err)
		return false, fmt.Errorf("连接失败")
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		logger.Error("认证连接失败，请检查地址")
		return false, fmt.Errorf("连接失败")
	}

	tokenMap["token"] = resultMap["data"].(string)

	return true, nil

}

// getDekCipherText 获取kek
func (client *KadpClient) getDekCipherText(label string, length int) error {

	reqMap := map[string]interface{}{
		"label":  label,
		"length": length,
	}

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek_text", tokenMap, reqMap)
	if err != nil {
		logger.Error("Failed to send request:", err)
		return errors.New("failed to send request")
	}

	resultMap := result.(map[string]interface{})
	code := resultMap["code"].(float64)

	if code == 4604 {
		client.authStatus, err = client.init()
		if err != nil {
			logger.Error("连接失败", err)
			return err
		}
		result, err = utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek_text", tokenMap, reqMap)
		if err != nil {
			logger.Error("", err)
			return err
		}
		resultMap = result.(map[string]interface{})
	}
	data := resultMap["data"].(string)

	privateKey := keyPair["privateKey"]
	dekText, err := rsaDecryptWithPrivateKey(privateKey, data)

	if err != nil {
		logger.Error("failed to decrypt:", err)
		return errors.New("failed to decrypt")
	}

	var TextJson map[string]string
	err = json.Unmarshal([]byte(dekText), &TextJson)
	if err != nil {
		logger.Error("解析 JSON 失败:", err)
		return err
	}

	versionValue := TextJson["version"]

	client.labelCipherText[label] = dekText
	client.version = versionValue
	_, err = client.cipherTextDecrypt(label)
	if err != nil {
		return err
	}

	return err

}

// cipherTextDecrypt 进行dek解密
func (client *KadpClient) cipherTextDecrypt(label string) (string, error) {
	dekCipherReq := client.labelCipherText[label]

	var TextJson map[string]string
	err := json.Unmarshal([]byte(dekCipherReq), &TextJson)
	if err != nil {
		logger.Error("解析 JSON 失败:", err)
		return "", err
	}

	result, err := utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek", tokenMap, TextJson)
	if err != nil {
		logger.Error("请求dek解密失败", err)
		return "", err
	}

	resultMap := result.(map[string]interface{})
	code := resultMap["code"].(float64)
	if code == 4604 {
		client.authStatus, err = client.init()
		if err != nil {
			return "", err
		}
		result, err = utils.SendRequest("POST", client.domain+"/v1/ksp/open_api/dek", tokenMap, dekCipherReq)
		if err != nil {
			logger.Error("请求失败", err)
			return "", err
		}
		resultMap = result.(map[string]interface{})
	}
	dek := resultMap["data"].(string)
	privateKey := keyPair["privateKey"]
	dekKeyBase, err := rsaDecryptWithPrivateKey(privateKey, dek)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	keyEntry := utils.CreateKeyEntry([]byte(dekKeyBase))
	utils.StoreSecretKey(label, keyEntry, client.keyStore, client.keyStoreFileName, []byte(client.keyStorePassWord))
	if err != nil {
		return "", err
	}
	client.keyMap[label] = dekKeyBase
	return dekKeyBase, nil

}

// getKey keystore密钥库获取key
func (client *KadpClient) getKey(length int, label string) error {
	if !client.authStatus {
		return nil
	}

	if length != 16 && length != 32 && length != 24 {
		return errors.New("length parameter error, can only be 16-24-32")
	}

	if label == "" {
		return errors.New("label parameter cannot be empty")
	}

	keyEntry, err := client.keyStore.GetPrivateKeyEntry(label, []byte("shanghaiandanggongsi"))
	if err != nil {
		logger.Info("keystore中不存在")
	}
	key := string(keyEntry.PrivateKey)
	if key == "" {
		if _, ok := client.keyMap[label]; !ok {
			err = client.getDekCipherText(label, length)
			if err != nil {
				logger.Error(err)
				return err
			}
		} else {
			_, err = client.cipherTextDecrypt(label)
			if err != nil {
				logger.Error(err)
				return err
			}

		}

		keyEntry, err = client.keyStore.GetPrivateKeyEntry(label, []byte("shanghaiandanggongsi"))
		if err != nil {
			logger.Debug("keystore中不存在")
		}
		key = string(keyEntry.PrivateKey)
	}

	if _, ok := client.keyMap[label]; !ok {
		client.keyMap[label] = key
	}

	return nil
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

	myKeyMode := cipher.NewCBCDecrypter(block, iv)
	myKeyMode.CryptBlocks(plaintext, decodeCiphertext)

	// 去除填充数据
	myKeyPadding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-myKeyPadding]

	// 创建正则表达式模式，匹配非可见字符和特殊字符
	pattern := "[[:cntrl:]]"

	// 使用正则表达式替换乱码部分
	re := regexp.MustCompile(pattern)
	trimmedToken := re.ReplaceAllString(string(plaintext), "")

	return trimmedToken, nil
}

func (client *KadpClient) FpeEncipher(plaintext string, fpe Fpe, tweak, alphabet string, length int, label string, start, end int) (string, error) {

	if end-start < 5 || start < 0 || end < 0 {
		return "", errors.New("开始位到结束位长度最少为6")
	}
	if len(plaintext) < end {
		return "", errors.New("结束位超出范围")
	}

	var err error
	if _, ok := client.keyMap[label]; !ok {
		err = client.getKey(length, label)
		if err != nil {
			return "", err
		}
	}
	key := client.keyMap[label]

	var ciphertext string
	switch fpe {
	case FF1:
		ciphertext, err = ff1Encrypt(plaintext, key, tweak, len([]rune(alphabet)), start, end, alphabet)
	case FF3:
		ciphertext, err = ff3Encrypt(plaintext, key, tweak, len([]rune(alphabet)), start, end, alphabet)
	default:
		err = fmt.Errorf("invalid choose value")
		return "", err
	}
	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) FpeDecipher(ciphertext string, fpe Fpe, tweak, alphabet string, length int, label string, start, end int) (string, error) {

	if end-start < 5 || start < 0 || end < 0 {
		return "", errors.New("开始位到结束位长度最少为6")
	}
	if len(ciphertext) < end {
		return "", errors.New("结束位超出范围")
	}
	var err error

	if _, ok := client.keyMap[label]; !ok {
		err = client.getKey(length, label)
		if err != nil {
			return "", err
		}
	}
	key := client.keyMap[label]

	var plaintext string
	switch fpe {
	case FF1:
		plaintext, err = ff1Decrypt(ciphertext, key, tweak, len([]rune(alphabet)), start, end, alphabet)
	case FF3:
		plaintext, err = ff3Decrypt(ciphertext, key, tweak, len([]rune(alphabet)), start, end, alphabet)
	default:
		err = fmt.Errorf("invalid choose value")
		return "", err
	}
	if err != nil {
		return "", err
	}

	return plaintext, err
}

func (client *KadpClient) Encipher(plaintext []byte, design Symmetry, modeVal Mode, paddingVal Padding, length int, label, iv string) (string, error) {
	var err error

	if _, ok := client.keyMap[label]; !ok {
		err = client.getKey(length, label)
		if err != nil {
			return "", err
		}
	}
	key := client.keyMap[label]

	var ciphertext string

	switch modeVal {
	case CBC:
		if paddingVal == NoPadding {
			ciphertext, err = aseCbcNoPadEncrypt(plaintext, []byte(iv), key, design)
		} else {
			ciphertext, err = aseCbcPaddingEncrypt(plaintext, []byte(iv), key, paddingVal, design)
		}
	case CTR:
		if paddingVal == NoPadding {
			ciphertext, err = aesCtrNoPadEncrypt(plaintext, []byte(iv), key, design)
		} else {
			ciphertext, err = aesCtrPaddingEncrypt(plaintext, []byte(iv), key, paddingVal, design)
		}
	case ECB:
		if paddingVal == NoPadding {
			ciphertext, err = aesEcbNoPadEncrypt(plaintext, key, design)
		} else {
			ciphertext, err = aesEcbPaddingEncrypt(plaintext, key, paddingVal, design)
		}

	case CFB:
		if paddingVal == NoPadding {
			ciphertext, err = aesCfbNoPadEncrypt(plaintext, []byte(iv), key, design)
		} else {
			ciphertext, err = aesCfbPaddingEncrypt(plaintext, []byte(iv), key, paddingVal, design)
		}
	case OFB:
		if paddingVal == NoPadding {
			ciphertext, err = aesOfbNoPadEncrypt(plaintext, []byte(iv), key, design)
		} else {
			ciphertext, err = aesOfbPaddingEncrypt(plaintext, []byte(iv), key, paddingVal, design)
		}
	case CGM:
		if paddingVal == NoPadding {
			ciphertext, err = aesGcmNoPadEncrypt(plaintext, key, design)
		} else {
			ciphertext, err = aesGcmPaddingEncrypt(plaintext, key, paddingVal, design)
		}
	}

	if err != nil {
		return "", err
	}

	return ciphertext, err
}

func (client *KadpClient) Decipher(ciphertext string, design Symmetry, modeVal Mode, paddingVal Padding, length int, label, iv string) (string, error) {
	var err error

	if _, ok := client.keyMap[label]; !ok {
		err = client.getKey(length, label)
		if err != nil {
			return "", err
		}
	}
	key := client.keyMap[label]

	var plaintext string
	switch modeVal {
	case CBC:
		if paddingVal == NoPadding {
			plaintext, err = aseCbcNoPadDecrypt(ciphertext, key, []byte(iv), design)
		} else {
			plaintext, err = aseCbcPaddingDecrypt(ciphertext, key, []byte(iv), paddingVal, design)
		}

	case CTR:
		if paddingVal == NoPadding {
			plaintext, err = aesCtrNoPadDecrypt(ciphertext, key, []byte(iv), design)
		} else {
			plaintext, err = aesCtrPaddingDecrypt(ciphertext, key, []byte(iv), paddingVal, design)
		}
	case ECB:
		if paddingVal == NoPadding {
			plaintext, err = aesEcbNoPadDecrypt(ciphertext, key, design)
		} else {
			plaintext, err = aesEcbPaddingDecrypt(ciphertext, key, paddingVal, design)
		}
	case CFB:
		if paddingVal == NoPadding {
			plaintext, err = aesCfbNoPadDecrypt(ciphertext, key, []byte(iv), design)
		} else {
			plaintext, err = aesCfbPaddingDecrypt(ciphertext, key, []byte(iv), paddingVal, design)
		}
	case OFB:
		if paddingVal == NoPadding {
			plaintext, err = aesOfbNoPadDecrypt(ciphertext, key, []byte(iv), design)
		} else {
			plaintext, err = aesOfbPaddingDecrypt(ciphertext, key, []byte(iv), paddingVal, design)
		}
	case CGM:
		if paddingVal == NoPadding {
			plaintext, err = aesGcmNoPadDecrypt(ciphertext, key, design)
		} else {
			plaintext, err = aesGcmPaddingDecrypt(ciphertext, key, paddingVal, design)
		}

	}

	if err != nil {
		return "", err
	}

	return plaintext, err
}

func (client *KadpClient) AsymmetricKeyPair(design Asymmetric) (publicKey string, privateKey string, err error) {
	var pub string
	var pri string
	var errs error

	switch design {
	case RSA:
		pub, pri, errs = rsaKeyGenerator()
		if errs != nil {
			return "", "", errs
		}
	case SM2:
		pub, pri, errs = sm2GenerateKey()
		if errs != nil {
			return "", "", errs
		}
	default:
		errs = fmt.Errorf("invalid choose value")
		return "", "", errs
	}

	return pub, pri, nil
}

func (client *KadpClient) AsymmetricPubEncrypt(plaintext string, design Asymmetric, publicKey string) (string, error) {

	var ciphertext string
	var err error
	switch design {
	case RSA:
		ciphertext, err = rsaEncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			return "", err
		}
	case SM2:
		ciphertext, err = sm2PubEncrypt(publicKey, plaintext)
		if err != nil {
			return "", err
		}
	default:
		err = fmt.Errorf("invalid choose value")
		return "", err
	}

	return ciphertext, nil
}

func (client *KadpClient) AsymmetricPriDecrypt(ciphertext string, design Asymmetric, privateKey string) (string, error) {

	var plaintext string
	var err error
	switch design {
	case RSA:
		plaintext, err = rsaDecryptWithPrivateKey(privateKey, ciphertext)
		if err != nil {
			return "", err
		}
	case SM2:
		plaintext, err = sm2PriDecrypt(privateKey, ciphertext)
		if err != nil {
			return "", err
		}
	default:
		err = fmt.Errorf("invalid choose value")
		return "", err
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

func (client *KadpClient) Hmac(message []byte, label string, length int) (string, error) {
	var err error

	if _, ok := client.keyMap[label]; !ok {
		err = client.getKey(length, label)
		if err != nil {
			return "", err
		}
	}
	key := client.keyMap[label]

	cipherText := generateHMAC([]byte(key), message)

	return cipherText, nil
}
func (client *KadpClient) HmacVerify(message []byte, hmacVal, label string, length int) (bool, error) {
	var err error

	if _, ok := client.keyMap[label]; !ok {
		err = client.getKey(length, label)
		if err != nil {
			return false, err
		}
	}
	key := client.keyMap[label]

	valid, err := verifyIntegrity([]byte(key), message, hmacVal)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func (client *KadpClient) SHASum(message []byte, shaHash Hash) (string, error) {

	var cipherText string
	var err error
	switch shaHash {
	case Sha1:
		cipherText = sha1Sum(message)
	case Sha256:
		cipherText = sha256Sum(message)
	default:
		err = fmt.Errorf("invalid choose value")
		return "", err
	}
	return cipherText, nil
}
