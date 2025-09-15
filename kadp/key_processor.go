package kadp

import (
	"errors"
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/order"
	"github.com/andang-secure/kadp-go/utils"
	"github.com/andang-secure/kadp-go/utils/aes_alg"
	"github.com/mitchellh/mapstructure"
)

type keyProcessor struct {
	privateKey string
	domain     string
	header     map[string]string
}

func (k *keyProcessor) fetchAndCacheKek(label string, length int) ([]byte, error) {

	result, err := utils.SendRequest(configs.POST, k.domain+configs.KEK_URL, k.header, order.KekReq{
		Label:  label,
		Length: length,
	})

	if err != nil {
		return nil, fmt.Errorf("连接失败")
	}

	// 防止空指针
	if result == nil {
		return nil, errors.New("响应数据为空")
	}

	// 类型断言并转换响应结果
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, errors.New("响应数据格式错误")
	}

	// 将 map 转换为 kekRes 结构体（避免 Marshal/Unmarshal）
	var kekRes order.KmsRes
	if err := mapstructure.Decode(resultMap, &kekRes); err != nil {
		return nil, fmt.Errorf("响应数据转换失败: %w", err)
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

	keyEntry := utils.CreateKeyEntry(decryptedKek)

	err = utils.NewKeyStoreObj().StoreSecretKey(label, keyEntry)
	if err != nil {
		return nil, fmt.Errorf("KeyStore存储异常: %w", err)
	}
	return decryptedKek, nil
}

func (k *keyProcessor) decryptKek(encryptedKek string) ([]byte, error) {

	key, err := rsaDecryptWithPrivateKey(k.privateKey, encryptedKek)
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

func (k *keyProcessor) decryptDek(encryptedDek, kek []byte) ([]byte, error) {
	decryptKey, err := aes_alg.AesCBCDecrypt(encryptedDek, kek, kek)
	if err != nil {
		return nil, fmt.Errorf("解密密钥失败: %w", err)
	}
	return decryptKey, err
}

func (k *keyProcessor) retrieveOrFetchDekKey(label string, cipherKey []byte) ([]byte, error) {

	kek, err := utils.NewKeyStoreObj().RetrieveSecretKey(label)
	if err != nil || kek == nil {
		kek, err = k.fetchAndCacheKek(label, len(cipherKey))
		if err != nil {
			return nil, err
		}
		decryptKey, err := k.decryptDek(cipherKey, kek)
		if err != nil {
			return nil, fmt.Errorf("解密密钥失败: %w", err)
		}
		return decryptKey, nil
	}
	decryptKey, err := k.decryptDek(cipherKey, kek)
	if err != nil {
		return nil, fmt.Errorf("解密密钥失败: %w", err)
	}
	return decryptKey, nil
}

func (k *keyProcessor) encryptDek(encryptedDek, kek []byte) ([]byte, error) {
	encryptKey, err := aes_alg.AesCBCEncrypt(encryptedDek, kek, kek)
	if err != nil {
		return nil, fmt.Errorf("加密密钥失败: %w", err)
	}
	return encryptKey, err
}
