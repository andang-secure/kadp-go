package utils

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	CaCrt1  = "C:\\Users\\13299\\go\\src\\kadp\\utils\\tls\\ca.crt"
	CliCrt1 = "C:\\Users\\13299\\go\\src\\kadp\\utils\\tls\\client_sign.crt"
	CliKey1 = "C:\\Users\\13299\\go\\src\\kadp\\utils\\tls\\client_sign.key"
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

	// 处理响应数据
	logger.Debug("Response Data:", result)
	return result, nil
}

func SendSdkAuthRequest(method, url string, header map[string]string, params interface{}, pri string, pub string) (interface{}, error) {
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
	data1, err := SortJSONKeysByASCII(string(data))
	paramsBuffer := bytes.NewBuffer(data)
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, paramsBuffer)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write([]byte(data1))
	sha256Bytes := hash.Sum(nil)
	// 转换为大写十六进制字符串
	contentSHA256 := strings.ToUpper(hex.EncodeToString(sha256Bytes))
	contentType := "application/json"
	apiName := "Encrypt"

	headerReq := NewRequest()

	headerReq.Headers["Method"] = method
	headerReq.Headers["content-sha256"] = contentSHA256
	headerReq.Headers["content-type"] = contentType
	headerReq.Headers["date"] = time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	headerReq.Headers["x-ksp-acccesskeyid"] = pub //base64编码
	headerReq.Headers["x-ksp-apiname"] = apiName

	strToSign, _err := GetStringToSign(method, headerReq.Headers)
	if _err != nil {
		logger.Error("组织签名字符串 error:", _err)
		return "", errors.New("组织签名字符串 error")
	}

	//logger.Info("签名字符串：", strToSign)

	//3.私钥签名参数
	signStrBase64, err := SignString(strToSign, pri)
	if _err != nil {
		logger.Error("私钥签名 error:", _err)
		return "", errors.New("私钥签名 error")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for k, v := range headerReq.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Sign-Header", signStrBase64)
	//logger.Info("********************参数验签*****************************")
	//logger.Info("r=", req)
	//logger.Info("*************************************************")
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
		return nil, errors.New("Response decoding error")
	}

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

func AuthSendRequest(method, url string, params interface{}) (interface{}, error) {
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
	// 处理响应数据
	logger.Debug("Response Data:", result)
	return result, nil
}

func HttpTlsPostReq(url string, params interface{}) (interface{}, error) {
	//启用双向认证
	config, err := createClientGMTLSConfig(CliKey1, CliCrt1, []string{CaCrt1})
	if err != nil {
		fmt.Println("err=", err)
	}
	httpClient := gmtls.NewCustomHTTPSClient(config)
	data, err := json.Marshal(params)
	if err != nil {
	}
	paramsBuffer := bytes.NewBuffer(data)
	response, err := httpClient.Post(url, "application/json;charset=utf-8", paramsBuffer)
	//req, err := http.NewRequest("POST", url, paramsBuffer)
	//req.Header.Set("Content-Type", "application/json;charset=utf-8")
	//
	//httpClient.Do(req)
	//
	//response, err := httpClient.Get("https://192.168.0.174:50055")

	if err != nil {
		fmt.Println("err=", err)
	}
	defer response.Body.Close()
	//raw, err := ioutil.ReadAll(response.Body)
	//if err != nil {
	//	fmt.Println("err=", err)
	//}

	// 读取响应体
	var result map[string]interface{}

	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		logger.Error("Response decoding error:", err)
		return nil, err
	}
	// 处理响应数据
	logger.Debug("Response Data:", result)
	return result, nil
}

func createClientGMTLSConfig(keyPath string, certPath string, caPaths []string) (*gmtls.Config, error) {

	cfg := &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
	}
	cfg.Certificates = []gmtls.Certificate{}
	if keyPath != "" && certPath != "" {
		cert, err := gmtls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load gm X509 keyPair error: %v", err)
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	var pool *x509.CertPool = nil
	if len(caPaths) > 0 {
		pool = x509.NewCertPool()
		for _, certPath := range caPaths {
			caCrt, err := ioutil.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			ok := pool.AppendCertsFromPEM(caCrt)
			if !ok {
				return nil, fmt.Errorf("append cert to pool fail at %s", certPath)
			}
		}
	}

	cfg.MinVersion = gmtls.VersionGMSSL
	cfg.MaxVersion = gmtls.VersionTLS12

	cfg.PreferServerCipherSuites = true
	// cfg.CipherSuites use default value []uint16{GMTLS_SM2_WITH_SM4_SM3, GMTLS_ECDHE_SM2_WITH_SM4_SM3}

	cfg.RootCAs = pool
	//cfg.ServerName = "localhost"
	cfg.InsecureSkipVerify = false
	cfg.ServerName = "192.168.0.200"

	return cfg, nil

}

func SendTLSRequest(method, url string, header map[string]string, params interface{}) (interface{}, error) {
	//启用双向认证
	config, err := createClientGMTLSConfig(CliKey1, CliCrt1, []string{CaCrt1})
	if err != nil {
		fmt.Println("err=", err)
	}
	httpClient := gmtls.NewCustomHTTPSClient(config)
	data, err := json.Marshal(params)
	if err != nil {
	}
	paramsBuffer := bytes.NewBuffer(data)

	req, err := http.NewRequest("POST", url, paramsBuffer)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	for k, v := range header {
		req.Header.Set(k, v)
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	//response, err := httpClient.Get("https://192.168.0.174:50055")

	if err != nil {
		fmt.Println("err=", err)
	}
	defer response.Body.Close()
	//raw, err := ioutil.ReadAll(response.Body)
	//if err != nil {
	//	fmt.Println("err=", err)
	//}

	// 读取响应体
	var result map[string]interface{}

	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		logger.Error("Response decoding error:", err)
		return nil, err
	}
	// 处理响应数据
	logger.Debug("Response Data:", result)
	return result, nil

}
