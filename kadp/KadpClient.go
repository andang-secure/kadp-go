package kadp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/order"
	"github.com/andang-secure/kadp-go/utils"
	"github.com/andang-secure/kadp-go/utils/aes_alg"
	"github.com/andang-secure/kadp-go/utils/cache"
	logger "github.com/sirupsen/logrus"
	"runtime"
)

type KadpImpl interface {
	CreateCipherKey(length int, label string) ([]byte, error)
	FpeEncipher(req *FpeEncipherRequest) (string, error)
	FpeDecipher(req *FpeDecipherRequest) (string, error)
	Encipher(req *EncipherRequest) (string, error)
	Decipher(req *DecryptRequest) ([]byte, error)
	AsymmetricKeyPair(design Asymmetric) (publicKey string, privateKey string, err error)
	AsymmetricEncrypt(req *AsymmetricEncryptRequest) (string, error)
	AsymmetricDecrypt(req *AsymmetricDecryptRequest) (string, error)
	SM2Sign(req *SM2SignRequest) (r, s string, err error)
	SM2Verify(req *SM2VerifyRequest) (bool, error)
	RsaSign(req *RsaSignRequest) (string, error)
	RsaVerify(req *RsaVerifyRequest) (bool, error)
	DigestEncrypt(plaintext string) string
	Hmac(req *HmacRequest) (string, error)
	HmacVerify(req *HmacVerifyRequest) (bool, error)
	SHASum(message []byte, shaHash Hash) (string, error)
}

type KadpClient struct {
	config       *configs.KmsConfig
	header       map[string]string
	version      string
	authStatus   bool
	keyProcessor *keyProcessor
	KeyManager   *KeyManager
}

// NewKADPClient 初始化
func NewKADPClient(config *configs.KmsConfig) (*KadpClient, error) {

	decodeToken, err := base64.StdEncoding.DecodeString(config.Credential)
	if err != nil {
		return nil, fmt.Errorf("token base64 decode err")
	}
	decryptToken, err := aes_alg.AesDecrypt(decodeToken, []byte(configs.KEY))
	if err != nil {
		return nil, fmt.Errorf("解密密钥失败: %w", err)
	}
	logger.Debug("解析出Token", len(decryptToken))
	KADPClient := &KadpClient{
		config: config,
		header: map[string]string{
			configs.TOKEN: string(decryptToken),
		},
	}
	utils.KeystoreFileName = config.KeystoreFileName
	utils.KeystorePassword = config.KeystorePassword
	KADPClient.authStatus, err = KADPClient.init()
	if err != nil {
		return nil, err
	}

	return KADPClient, nil
}

func (client *KadpClient) registerAuth(addr, system, ip string) error {
	// 构造请求参数
	registerReq := order.RegisterReq{
		MacAddr: addr,
		IP:      ip,
		System:  system,
		Token:   client.config.RegisterToken,
	}
	// 发送认证请求
	result, err := utils.AuthSendRequest(configs.POST, client.config.Domain+configs.REGISTE_URL, registerReq)
	if err != nil {
		return fmt.Errorf("认证请求失败: %w", err)
	}
	// 解析响应
	var registerRes order.KmsRes
	if err := utils.ParseResponse(result, &registerRes); err != nil {
		return fmt.Errorf("注册认证响应处理失败: %w", err)
	}
	// 检查业务状态码
	if registerRes.Code != 0 {
		return fmt.Errorf("KMS服务器返回错误: %s (code: %d)", registerRes.Msg, registerRes.Code)
	}

	return nil
}

// init 开始加载进行连接
func (client *KadpClient) init() (bool, error) {

	mac, err := utils.GetMac()
	if err != nil {
		return false, fmt.Errorf("获取系统Mac失败: %v", err)
	}
	system := runtime.GOOS

	ip, err := utils.GetOutBoundIP()
	if err != nil {
		return false, fmt.Errorf("系统IP信息失败: %v", err)
	}

	//开始客户端认证
	err = client.registerAuth(mac, ip, system)
	if err != nil {
		return false, fmt.Errorf("获取系统失败: %v", err)
	}

	logger.Debug("* register /Client authentication result: true")
	logger.Debug("===============end register authentication ...=================")
	logger.Debug("")

	var publicKey, privateKey string
	switch configs.Alg {
	case configs.RSA:
		publicKey, privateKey, err = rsaKeyGenerator()
		if err != nil {
			return false, fmt.Errorf("init err: %v", err)
		}
	case configs.SM2:
		//暂未有sm2实现
	}

	publicKey = base64.StdEncoding.EncodeToString([]byte(publicKey))

	// 构造请求参数
	authReq := order.AuthReq{
		Alg:     configs.Alg,
		IP:      ip,
		MacAddr: mac,
		Pub:     publicKey,
		System:  system,
	}

	logger.Debug("===============start AUTH authentication ...=================")
	logger.Debug(authReq)
	result, err := utils.SendRequest(configs.POST, client.config.Domain+configs.AUTH_URL, client.header, authReq)
	if err != nil {
		logger.Error("Failed to send request:", err)
		return false, fmt.Errorf("连接失败")
	}

	// 解析认证响应
	var authRes order.KmsAuthRes
	if err := utils.ParseResponse(result, &authRes); err != nil {
		return false, fmt.Errorf("身份认证响应处理失败: %w", err)
	}

	// 检查认证结果
	if authRes.Code != 0 {
		return false, fmt.Errorf("KMS服务器返回认证错误: %s (code: %d)", authRes.Msg, authRes.Code)
	}

	HeaderMap := map[string]string{
		configs.TOKEN: authRes.Data.Token,
	}

	client.keyProcessor = newKeyProcessor(privateKey, client.config.Domain, HeaderMap)
	client.KeyManager = newKeyManager(client.config.Domain, HeaderMap)

	logger.Debug("* AUTH /Client authentication result: true")
	logger.Debug("===============end AUTH authentication ...=================")
	logger.Debug("")
	return true, nil

}
func (client *KadpClient) CreateCipherKey(length int, label string) ([]byte, error) {
	if !client.authStatus {
		return nil, errors.New("KMS authentication failed")
	}
	if label == "" {
		return nil, errors.New("label cannot be empty")
	}
	if length != 16 && length != 24 && length != 32 {
		return nil, errors.New("key length must be 16, 24, or 32")
	}
	// 首先检查缓存中是否已有密钥
	if cachedKey, exists := cache.KeyCache.Retrieve(label); exists {
		logger.Debugf("从缓存中获取密钥: %s", label)
		return cachedKey, nil
	}
	kek, err := utils.NewKeyStoreObj().RetrieveSecretKey(label)
	if err != nil && kek == nil {
		logger.Debug("* CreateCipherKey", len(kek))

		kek, err = client.keyProcessor.fetchAndCacheKek(label, length)
		if err != nil {
			return nil, fmt.Errorf("获取kek密钥失败: %w", err)
		}
	}
	deyKey, err := client.keyProcessor.decryptKmsKek(kek)
	cache.KeyCache.Store(label, deyKey)
	logger.Debug("* CreateCipherKey", len(deyKey))
	//randomBytes, err := utils.GenerateRandomBytes(length)
	//if err != nil {
	//	return nil, err
	//}
	//
	//enyKey, err := client.keyProcessor.encryptDek(randomBytes, kek)
	//if err != nil {
	//	return nil, fmt.Errorf("加密dek密钥失败: %w", err)
	//}

	logger.Debug("* 创建密文密钥", len(deyKey))
	return deyKey, nil
}

func (client *KadpClient) FpeEncipher(req *FpeEncipherRequest) (ciphertext string, err error) {
	if !client.authStatus {
		return "", errors.New("KMS authentication failed")
	}
	if req.End-req.Start < 5 || req.Start < 0 || req.End < 0 {
		return "", errors.New("开始位到结束位长度最少为6")
	}
	if len(req.Plaintext) < req.End {
		return "", errors.New("结束位超出范围")
	}

	// 从缓存中获取密钥
	key, err := client.keyProcessor.retrieveOrFetchDekKey(req.Label)
	if err != nil {
		return "", fmt.Errorf("获取dek密钥失败: %w", err)
	}

	fpe := req.Fpe
	switch fpe {
	case FF1:
		ciphertext, err = ff1Encrypt(req.Plaintext, key, []byte(req.Tweak), len([]rune(req.Alphabet)), req.Start, req.End, req.Alphabet)
	case FF3:
		ciphertext, err = ff3Encrypt(req.Plaintext, key, []byte(req.Tweak), len([]rune(req.Alphabet)), req.Start, req.End, req.Alphabet)
	default:
		return "", errors.New("invalid choose value")
	}
	if err != nil {
		return "", fmt.Errorf("加密失败: %w", err)
	}

	return ciphertext, err
}

func (client *KadpClient) FpeDecipher(req *FpeDecipherRequest) (plaintext string, err error) {

	if !client.authStatus {
		return "", errors.New("KMS authentication failed")
	}
	if req.End-req.Start < 5 || req.Start < 0 || req.End < 0 {
		return "", errors.New("开始位到结束位长度最少为6")
	}
	if len(req.Ciphertext) < req.End {
		return "", errors.New("结束位超出范围")
	}
	// 从缓存中获取密钥
	key, err := client.keyProcessor.retrieveOrFetchDekKey(req.Label)
	if err != nil {
		return "", fmt.Errorf("获取dek密钥失败: %w", err)
	}

	switch req.Fpe {
	case FF1:
		plaintext, err = ff1Decrypt(req.Ciphertext, key, []byte(req.Tweak), len([]rune(req.Alphabet)), req.Start, req.End, req.Alphabet)
	case FF3:
		plaintext, err = ff3Decrypt(req.Ciphertext, key, []byte(req.Tweak), len([]rune(req.Alphabet)), req.Start, req.End, req.Alphabet)
	default:
		return "", errors.New("invalid choose value")
	}
	if err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}

	return plaintext, err
}

func (client *KadpClient) Encipher(req *EncipherRequest) (ciphertext string, err error) {

	if req.Plaintext == nil {
		return "", errors.New("plaintext cannot be empty")
	}
	key, err := client.keyProcessor.retrieveOrFetchDekKey(req.Label)
	if err != nil {
		return "", fmt.Errorf("获取dek密钥失败: %w", err)
	}
	logger.Debug("* Encipher", len(key))

	switch req.Mode {
	case CBC:
		if req.Padding == NoPadding {
			ciphertext, err = aseCbcNoPadEncrypt(req, key)
		} else {
			ciphertext, err = aseCbcPaddingEncrypt(req, key)
		}
	case CTR:
		if req.Padding == NoPadding {
			ciphertext, err = aesCtrNoPadEncrypt(req, key)
		} else {
			ciphertext, err = aesCtrPaddingEncrypt(req, key)
		}
	case ECB:
		if req.Padding == NoPadding {
			ciphertext, err = aesEcbNoPadEncrypt(req, key)
		} else {
			ciphertext, err = aesEcbPaddingEncrypt(req, key)
		}

	case CFB:
		if req.Padding == NoPadding {
			ciphertext, err = aesCfbNoPadEncrypt(req, key)
		} else {
			ciphertext, err = aesCfbPaddingEncrypt(req, key)
		}
	case OFB:
		if req.Padding == NoPadding {
			ciphertext, err = aesOfbNoPadEncrypt(req, key)
		} else {
			ciphertext, err = aesOfbPaddingEncrypt(req, key)
		}
	case CGM:
		if req.Padding == NoPadding {
			ciphertext, err = aesGcmNoPadEncrypt(req, key)
		} else {
			ciphertext, err = aesGcmPaddingEncrypt(req, key)
		}
	}

	if err != nil {
		return "", fmt.Errorf("加密失败: %w", err)
	}

	return ciphertext, err
}

func (client *KadpClient) Decipher(req *DecryptRequest) (plaintext []byte, err error) {
	if req.Ciphertext == "" {
		return nil, errors.New("ciphertext cannot be empty")
	}
	key, err := client.keyProcessor.retrieveOrFetchDekKey(req.Label)
	if err != nil {
		return nil, fmt.Errorf("获取dek密钥失败: %w", err)
	}
	switch req.Mode {
	case CBC:
		if req.Padding == NoPadding {
			plaintext, err = aseCbcNoPadDecrypt(req, key)
		} else {
			plaintext, err = aseCbcPaddingDecrypt(req, key)
		}

	case CTR:
		if req.Padding == NoPadding {
			plaintext, err = aesCtrNoPadDecrypt(req, key)
		} else {
			plaintext, err = aesCtrPaddingDecrypt(req, key)
		}
	case ECB:
		if req.Padding == NoPadding {
			plaintext, err = aesEcbNoPadDecrypt(req, key)
		} else {
			plaintext, err = aesEcbPaddingDecrypt(req, key)
		}
	case CFB:
		if req.Padding == NoPadding {
			plaintext, err = aesCfbNoPadDecrypt(req, key)
		} else {
			plaintext, err = aesCfbPaddingDecrypt(req, key)
		}
	case OFB:
		if req.Padding == NoPadding {
			plaintext, err = aesOfbNoPadDecrypt(req, key)
		} else {
			plaintext, err = aesOfbPaddingDecrypt(req, key)
		}
	case CGM:
		if req.Padding == NoPadding {
			plaintext, err = aesGcmNoPadDecrypt(req, key)
		} else {
			plaintext, err = aesGcmPaddingDecrypt(req, key)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	return plaintext, err
}

func (client *KadpClient) AsymmetricKeyPair(design Asymmetric) (publicKey string, privateKey string, err error) {

	switch design {
	case RSA:
		publicKey, privateKey, err = rsaKeyGenerator()
		if err != nil {
			return "", "", fmt.Errorf("密钥对生成失败: %w", err)
		}
	case SM2:
		publicKey, privateKey, err = sm2GenerateKey()
		if err != nil {
			return "", "", fmt.Errorf("密钥对生成失败: %w", err)
		}
	default:
		return "", "", errors.New("invalid choose value")
	}

	return publicKey, privateKey, nil
}

func (client *KadpClient) AsymmetricEncrypt(req *AsymmetricEncryptRequest) (string, error) {

	var ciphertext string
	var err error
	switch req.Algorithm {
	case RSA:
		ciphertext, err = rsaEncryptWithPublicKey(req.PublicKey, req.Plaintext)
		if err != nil {
			return "", fmt.Errorf("加密失败: %w", err)
		}
	case SM2:
		ciphertext, err = sm2PubEncrypt(req.PublicKey, req.Plaintext)
		if err != nil {
			return "", fmt.Errorf("加密失败: %w", err)
		}
	default:
		return "", errors.New("invalid choose value")
	}

	return ciphertext, nil
}

func (client *KadpClient) AsymmetricDecrypt(req *AsymmetricDecryptRequest) (string, error) {

	var plaintext string
	var err error
	switch req.Algorithm {
	case RSA:
		plaintext, err = rsaDecryptWithPrivateKey(req.PrivateKey, req.Ciphertext)
		if err != nil {
			return "", fmt.Errorf("解密失败: %w", err)
		}
	case SM2:
		plaintext, err = sm2PriDecrypt(req.PrivateKey, req.Ciphertext)
		if err != nil {
			return "", fmt.Errorf("解密失败: %w", err)
		}
	default:
		return "", errors.New("invalid choose value")
	}

	return plaintext, nil
}

func (client *KadpClient) SM2Sign(req *SM2SignRequest) (r, s string, err error) {

	r, s, errs := sm2Sign(req.PrivateKey, []byte(req.Plaintext), req.Uid)
	if errs != nil {
		return "", "", errs
	}

	return r, s, nil
}

func (client *KadpClient) SM2Verify(req *SM2VerifyRequest) (bool, error) {

	VerifyBool, err := sm2Verify(req.PublicKey, []byte(req.Plaintext), req.Uid, req.R, req.S)
	if err != nil {
		return VerifyBool, err
	}

	return VerifyBool, nil
}

func (client *KadpClient) RsaSign(req *RsaSignRequest) (string, error) {

	sign, err := rsaSign(req.PrivateKey, []byte(req.Plaintext))
	if err != nil {
		return "", err
	}

	return sign, nil
}

func (client *KadpClient) RsaVerify(req *RsaVerifyRequest) (bool, error) {

	VerifyBool, err := rsaVerify(req.PublicKey, req.Signature, []byte(req.Plaintext))
	if err != nil {
		return VerifyBool, err
	}

	return VerifyBool, nil
}

func (client *KadpClient) DigestEncrypt(plaintext string) string {
	cipherText := sm3Encrypt([]byte(plaintext))
	return cipherText
}

func (client *KadpClient) Hmac(req *HmacRequest) (string, error) {
	key, err := client.keyProcessor.retrieveOrFetchDekKey(req.Label)
	if err != nil {
		return "", fmt.Errorf("获取dek密钥失败: %w", err)
	}
	cipherText := generateHMAC(key, req.Message)

	return cipherText, nil
}
func (client *KadpClient) HmacVerify(req *HmacVerifyRequest) (bool, error) {
	key, err := client.keyProcessor.retrieveOrFetchDekKey(req.Label)
	if err != nil {
		return false, fmt.Errorf("获取dek密钥失败: %w", err)
	}
	valid, err := verifyIntegrity(key, req.Message, req.HmacVal)
	if err != nil {
		return false, fmt.Errorf("验证失败: %w", err)
	}
	return valid, nil
}

func (client *KadpClient) SHASum(message []byte, shaHash Hash) (string, error) {

	var cipherText string
	switch shaHash {
	case Sha1:
		cipherText = sha1Sum(message)
	case Sha256:
		cipherText = sha256Sum(message)
	default:
		return "", errors.New("invalid choose value")
	}
	return cipherText, nil
}
