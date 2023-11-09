package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

func SendRequest(method, url string, header map[string]string, params interface{}) (interface{}, error) {
	// 创建自定义的TLS配置，禁用证书验证
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// 创建自定义的Transport，使用自定义的TLS配置
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	data, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	paramsBuffer := bytes.NewBuffer(data)
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, paramsBuffer)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	for k, v := range header {
		req.Header.Set(k, v)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()
	// 读取响应体
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		logger.Error("Response decoding error:", err)
		return nil, err
	}

	logger.Info("获取请求：", result)
	// 处理响应数据
	logger.Debug("Response Data:", result)
	return result, nil
}

func LoginRequest(method, url string, header map[string]string, params interface{}) ([]byte, error) {
	data, err := json.Marshal(params)
	fmt.Println(data)
	if err != nil {
		return nil, err
	}
	paramsBuffer := bytes.NewBuffer(data)
	client := &http.Client{}

	req, err := http.NewRequest(method, url, paramsBuffer)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	for k, v := range header {
		req.Header.Set(k, v)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
