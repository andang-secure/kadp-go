package kadp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/order"
	"github.com/andang-secure/kadp-go/utils"
	"github.com/andang-secure/kadp-go/utils/cache"
	logger "github.com/sirupsen/logrus"
	"strings"
)

type keyProcessor struct {
	privateKey string
	domain     string
	header     map[string]string
}

func newKeyProcessor(privateKey string, domain string, header map[string]string) *keyProcessor {
	return &keyProcessor{
		privateKey: privateKey,
		domain:     domain,
		header:     header,
	}
}

func (k *keyProcessor) fetchAndCacheKek(label string, length int, isStore int) ([]byte, error) {

	result, err := utils.SendRequest(configs.POST, k.domain+configs.KEK_URL, k.header, order.KekReq{
		Label:   label,
		Length:  length,
		IsStore: isStore,
	})

	logger.Debug("===============start KEK encryption ...=================")
	logger.Debug(result)
	if err != nil {
		return nil, fmt.Errorf("连接失败")
	}

	// 解析响应
	var kekRes order.KmsRes
	if err := utils.ParseResponse(result, &kekRes); err != nil {
		return nil, fmt.Errorf("kek请求响应处理失败: %w", err)
	}

	// 检查业务状态码
	if kekRes.Code != 0 {
		return nil, fmt.Errorf("ksm server err: %s", kekRes.Msg) // 修正错误包装方式
	}

	//decryptedKek
	decryptedKek, err := k.decryptKek(kekRes.Data)
	if err != nil {
		return nil, fmt.Errorf("解密密钥失败: %w", err)
	}
	logger.Debug("===============end KEK encryption ...=================")
	logger.Debug("kek res data :", string(decryptedKek))

	// 修复：使用 json.Unmarshal 解析 JSON 字符串
	var kekData order.KekData
	// 确保 decryptedKek 是有效的 JSON 字符串
	jsonData := strings.TrimSpace(string(decryptedKek))
	if err := json.Unmarshal([]byte(jsonData), &kekData); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w, 数据: %s", err, jsonData)
	}
	decodeKek, err := base64.StdEncoding.DecodeString(kekData.Cont)
	if err != nil {
		return nil, err
	}

	keyEntry := utils.CreateKeyEntry(decodeKek)

	err = utils.NewKeyStoreObj().StoreSecretKey(label, keyEntry)
	if err != nil {
		return nil, fmt.Errorf("KeyStore存储异常: %w", err)
	}
	logger.Debug("kek len:", len(keyEntry.PrivateKey))

	return decodeKek, nil
}

func (k *keyProcessor) decryptKek(encryptedKek string) ([]byte, error) {

	key, err := rsaDecryptWithPrivateKey(k.privateKey, encryptedKek)
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

//
//func (k *keyProcessor) decryptDek(encryptedDek, kek []byte) ([]byte, error) {
//	logger.Debug("decryptDek", len(kek))
//
//	decryptKey, err := aes_alg.AesCBCDecrypt(encryptedDek, kek, kek[:16])
//	if err != nil {
//		return nil, fmt.Errorf("解密密钥失败: %w", err)
//	}
//	logger.Debug("decryptDek", len(decryptKey))
//	return decryptKey, err
//}

//func (k *keyProcessor) retrieveOrFetchDekKey(label string, cipherKey []byte) ([]byte, error) {
//	logger.Debug("密文密钥开始解密", len(cipherKey))
//
//	kek, err := utils.NewKeyStoreObj().RetrieveSecretKey(label)
//	if err != nil {
//		logger.Debug("密钥不存在", err.Error())
//		kek, err = k.fetchAndCacheKek(label, 16)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	decryptKey, err := k.decryptDek(cipherKey, kek)
//	if err != nil {
//		return nil, fmt.Errorf("解密密钥失败: %w", err)
//	}
//	logger.Debug("密文密钥解密成功", len(decryptKey))
//	return decryptKey, nil
//}

//func (k *keyProcessor) encryptDek(encryptedDek, kek []byte) ([]byte, error) {
//	logger.Debug("encryptDek", len(kek))
//	encryptKey, err := aes_alg.AesCBCEncrypt(encryptedDek, kek, kek[:16])
//	if err != nil {
//		return nil, fmt.Errorf("加密密钥失败: %w", err)
//	}
//	return encryptKey, err
//}

func (k *keyProcessor) decryptKmsKek(kek []byte) ([]byte, error) {
	logger.Debug("decryptDek", len(kek))
	logger.Debug("decryptDek", base64.StdEncoding.EncodeToString(kek))

	result, err := utils.SendRequest(configs.POST, k.domain+configs.DEK_URL, k.header, order.KekData{
		Cont:    base64.StdEncoding.EncodeToString(kek),
		Version: "0",
	})

	logger.Debug("===============start DEK encryption ...=================")
	logger.Debug(result)
	if err != nil {
		return nil, fmt.Errorf("连接失败")
	}

	// 解析响应
	var kekRes order.KmsRes
	if err := utils.ParseResponse(result, &kekRes); err != nil {
		return nil, fmt.Errorf("kek请求响应处理失败: %w", err)
	}

	// 检查业务状态码
	if kekRes.Code != 0 {
		return nil, fmt.Errorf("ksm server err: %s", kekRes.Msg) // 修正错误包装方式
	}
	logger.Debug("获取dek密文完毕", kekRes.Data)

	//decryptedKek
	dek, err := k.decryptKek(kekRes.Data)
	if err != nil {
		return nil, fmt.Errorf("解密密钥失败: %w", err)
	}
	decodeDek, err := base64.StdEncoding.DecodeString(string(dek))
	if err != nil {
		return nil, fmt.Errorf("dek base64解密失败: %w", err)
	}
	logger.Debug("获取dek完毕=======", len(decodeDek))

	logger.Debug("===============end DEK encryption ...=================")

	return decodeDek, err
}

func (k *keyProcessor) retrieveOrFetchDekKey(label string) ([]byte, error) {

	if cachedKey, exists := cache.KeyCache.Retrieve(label); exists {
		logger.Debugf("从缓存中获取密钥: %s", label)
		return cachedKey, nil
	}

	kek, err := utils.NewKeyStoreObj().RetrieveSecretKey(label)
	if err != nil {
		logger.Debug("密钥不存在", err.Error())
		//kek, err = k.fetchAndCacheKek(label, 16,)
		//if err != nil {
		//	return nil, err
		//}
		//return nil, err
	}
	decryptKey, err := k.decryptKmsKek(kek)
	if err != nil {
		return nil, fmt.Errorf("解密kek密钥失败: %w", err)
	}
	cache.KeyCache.Store(label, decryptKey)
	logger.Debug("密文密钥解密成功", len(decryptKey))
	return decryptKey, nil
}
