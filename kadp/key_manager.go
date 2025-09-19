package kadp

import (
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/utils"
	logger "github.com/sirupsen/logrus"
)

type KeyManager struct {
	domain string
	header map[string]string
}

func newKeyManager(domain string, header map[string]string) *KeyManager {
	return &KeyManager{domain: domain, header: header}
}

// SecretKeyList 获取密钥列表
func (km *KeyManager) SecretKeyList(keyListParam *KeyListParam) (*KeyList, error) {
	logger.Debug("开始获取密钥列表")

	// 设置默认分页参数
	if keyListParam.Page == "" {
		keyListParam.Page = "1"
	}
	if keyListParam.PageSize == "" {
		keyListParam.PageSize = "10"
	}

	logger.Debug("分页参数:", km.header)

	keyListResp := keyListRes{}
	// 发送GET请求
	err := utils.GetRequest(configs.GET, km.domain+"/v1/ksp/open_api/key/list", km.header, map[string]interface{}{
		"page":      keyListParam.Page,     // 页码
		"page_size": keyListParam.PageSize, // 每页条数
	}, false, &keyListResp)

	if err != nil {
		return nil, fmt.Errorf("列表请求失败: %w", err)
	}
	// 检查业务状态码
	if keyListResp.Code != 0 {
		return nil, fmt.Errorf("ksm server err: %s", keyListResp.Msg) // 修正错误包装方式
	}

	return &keyListResp.Data, nil
}

func (km *KeyManager) CreateKey(req *CreateKeyRequest) (kid string, err error) {
	logger.Debug("开始创建密钥")
	if req.Name == "" {
		return "", fmt.Errorf("请输入密钥名称")
	}
	createKeyResp := createKeyRes{}

	err = utils.SendRequest2(configs.POST, km.domain+"/v1/ksp/open_api/key/create", km.header, req, false, &createKeyResp)
	if err != nil {
		return "", fmt.Errorf("创建密钥失败: %w", err)
	}
	if createKeyResp.Code != 0 {
		return "", fmt.Errorf("ksm server err: %s", createKeyResp.Msg) // 修正错误包装方式
	}
	return createKeyResp.Data.Kid, nil
}

func (km *KeyManager) GetKeyInfo(kid string) (*KeyInfoData, error) {
	logger.Debug("开始获取密钥信息")
	if kid == "" {
		return nil, fmt.Errorf("请输入密钥ID")
	}
	KeyInfoRes := keyInfoRes{}
	err := utils.GetRequest(configs.GET, km.domain+"/v1/ksp/open_api/key/info", km.header, map[string]interface{}{
		"kid": kid, // 页码
	}, false, &KeyInfoRes)

	if err != nil {
		return nil, fmt.Errorf("列表请求失败: %w", err)
	}
	// 检查业务状态码
	if KeyInfoRes.Code != 0 {
		return nil, fmt.Errorf("ksm server err: %s", KeyInfoRes.Msg) // 修正错误包装方式
	}
	return &KeyInfoRes.Data, nil
}

func (km *KeyManager) DeleteKey(kid string) error {
	logger.Debug("开始删除密钥")
	if kid == "" {
		return fmt.Errorf("请输入密钥ID")
	}
	deleteKeyResp := commonRes{}

	err := utils.SendRequest2(configs.DELETE, km.domain+"/v1/ksp/open_api/key/delete",
		km.header, &deleteKeyRequest{Kid: kid}, false, &deleteKeyResp)
	if err != nil {
		return fmt.Errorf("创建密钥失败: %w", err)
	}
	if deleteKeyResp.Code != 0 {
		return fmt.Errorf("ksm server err: %s", deleteKeyResp.Msg) // 修正错误包装方式
	}
	return nil
}

func (km *KeyManager) UpdateKey(req *UpdateKeyRequest) error {
	logger.Debug("开始修改密钥")
	if req.Kid == "" {
		return fmt.Errorf("请输入密钥ID")
	}
	updateKeyResp := commonRes{}

	err := utils.SendRequest2(configs.POST, km.domain+"/v1/ksp/open_api/key/update", km.header,
		req, false, &updateKeyResp)
	if err != nil {
		return fmt.Errorf("创建密钥失败: %w", err)
	}
	if updateKeyResp.Code != 0 {
		return fmt.Errorf("ksm server err: %s", updateKeyResp.Msg) // 修正错误包装方式
	}
	return nil
}

func (km *KeyManager) AddKeyVersion(kid string) error {
	logger.Debug("开始密钥版本添加")
	if kid == "" {
		return fmt.Errorf("请输入密钥ID")
	}
	addKeyVersionResp := commonRes{}

	err := utils.SendRequest2(configs.POST, km.domain+"/v1/ksp/open_api/key/addversion", km.header,
		&commonKidRequest{Kid: kid}, false, &addKeyVersionResp)
	if err != nil {
		return fmt.Errorf("创建密钥失败: %w", err)
	}
	if addKeyVersionResp.Code != 0 {
		return fmt.Errorf("ksm server err: %s", addKeyVersionResp.Msg) // 修正错误包装方式
	}
	return nil
}

func (km *KeyManager) CloneKey(req *CloneKeyRequest) error {
	logger.Debug("开始密钥克隆")
	if req.Kid == "" {
		return fmt.Errorf("请输入需要克隆的密钥ID")
	}
	if req.Name == "" {
		return fmt.Errorf("请输入新的密钥名称")
	}
	cloneKeyResp := commonRes{}

	err := utils.SendRequest2(configs.POST, km.domain+"/v1/ksp/open_api/key/clone", km.header,
		req, false, &cloneKeyResp)
	if err != nil {
		return fmt.Errorf("创建密钥失败: %w", err)
	}
	if cloneKeyResp.Code != 0 {
		return fmt.Errorf("ksm server err: %s", cloneKeyResp.Msg) // 修正错误包装方式
	}
	return nil
}

func (km *KeyManager) DistributeKey(req *CloneKeyRequest) error {
	logger.Debug("开始密钥版本添加")
	if req.Kid == "" {
		return fmt.Errorf("请输入需要克隆的密钥ID")
	}
	if req.Name == "" {
		return fmt.Errorf("请输入新的密钥名称")
	}
	cloneKeyResp := commonRes{}

	err := utils.SendRequest2(configs.POST, km.domain+"/v1/ksp/open_api/key/clone", km.header,
		req, false, &cloneKeyResp)
	if err != nil {
		return fmt.Errorf("创建密钥失败: %w", err)
	}
	if cloneKeyResp.Code != 0 {
		return fmt.Errorf("ksm server err: %s", cloneKeyResp.Msg) // 修正错误包装方式
	}
	return nil
}
