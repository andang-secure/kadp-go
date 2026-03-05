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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	CaCrt1  = "C:\\Users\\13299\\go\\src\\kadp\\utils\\tls\\ca.crt"
	CliCrt1 = "C:\\Users\\13299\\go\\src\\kadp\\utils\\tls\\client_sign.crt"
	CliKey1 = "C:\\Users\\13299\\go\\src\\kadp\\utils\\tls\\client_sign.key"
)

func SendRequest(method, url string, header map[string]string, params interface{}) (interface{}, error) {
	marshal, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	logger.Debug("请求参数:", string(marshal))
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
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	// 尝试解析JSON
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		logger.Error("JSON解析错误:", err)
		logger.Error("原始响应体:", string(body))
		return nil, fmt.Errorf("JSON解析失败: %w", err)
	}

	// 处理响应数据
	logger.Debug("响应数据:", result)
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

	strToSign, err := GetStringToSign(method, headerReq.Headers)
	if err != nil {
		logger.Error("组织签名字符串 error:", err)
		return "", errors.New("组织签名字符串 error")
	}

	//logger.Info("签名字符串：", strToSign)

	//3.私钥签名参数
	signStrBase64, err := SignString(strToSign, pri)
	if err != nil {
		logger.Error("私钥签名 error:", err)
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
	// 参数验证
	if url == "" {
		return nil, errors.New("URL 不能为空")
	}

	// 1. 预先序列化参数 (移到循环外，避免重复序列化)
	var reqData []byte
	if params != nil {
		var err error
		reqData, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("参数序列化失败：%w", err)
		}
	} else {
		reqData = []byte{}
	}

	// 创建自定义的 TLS 配置，禁用证书验证
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// 创建自定义的 Transport
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// 创建 HTTP 客户端
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	// 2. 定义最大重试次数
	const maxRetries = 3
	var lastErr error

	// 3. 循环执行请求
	for attempt := 1; attempt <= maxRetries; attempt++ {
		paramsBuffer := bytes.NewBuffer(reqData)

		// 创建 HTTP 请求
		req, err := http.NewRequest(method, url, paramsBuffer)
		if err != nil {
			return nil, fmt.Errorf("创建请求失败：%w", err)
		}

		// 设置请求头
		req.Header.Set("Content-Type", "application/json;charset=utf-8")

		// 发送请求
		response, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("发送请求失败：%w", err)
			logger.Warnf("网络请求失败 (尝试 %d/%d): %v", attempt, maxRetries, err)
			// 网络错误时，response 为 nil，无需 Close
			if attempt < maxRetries {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, lastErr
		}

		// 【关键修复】先读取所有响应数据到内存，然后再关闭 Body
		bodyBytes, readErr := ioutil.ReadAll(response.Body)

		// 立即关闭 Body，释放连接
		if closeErr := response.Body.Close(); closeErr != nil {
			logger.Warnf("关闭响应体失败：%v", closeErr)
		}

		// 如果读取失败，记录错误并决定是否重试
		if readErr != nil {
			lastErr = fmt.Errorf("读取响应体失败：%w", readErr)
			logger.Warnf("读取响应失败 (尝试 %d/%d): %v", attempt, maxRetries, readErr)
			if attempt < maxRetries {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, lastErr
		}

		// 4. 检查 HTTP 状态码 (使用已读取的 bodyBytes 进行日志记录)
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP 请求失败，状态码：%d", response.StatusCode)
			logger.Warnf("HTTP 状态码异常 (尝试 %d/%d): code=%d, body=%s", attempt, maxRetries, response.StatusCode, string(bodyBytes))
			if attempt < maxRetries {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, lastErr
		}

		// 替换原来的 json.Unmarshal 逻辑
		var result map[string]interface{}
		decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		decoder.UseNumber() // 关键：将数字解析为 json.Number 而非 float64

		if err := decoder.Decode(&result); err != nil {
			lastErr = fmt.Errorf("响应解析失败：%w", err)
			logger.Errorf("JSON 解析失败 (尝试 %d/%d): %v, 原始响应:%s", attempt, maxRetries, err, string(bodyBytes))
			if attempt < maxRetries {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, lastErr
		}
		// 6. 检查业务状态码 code 是否为 0
		codeVal, hasCode := result["code"]
		if hasCode {
			isSuccess := false
			switch v := codeVal.(type) {
			case json.Number:
				// 尝试转换为 int64 或 float64 进行比较
				iVal, err := v.Int64()
				if err == nil && iVal == 0 {
					isSuccess = true
				} else {
					fVal, _ := v.Float64()
					if fVal == 0 {
						isSuccess = true
					}
				}
			case float64:
				if v == 0 {
					isSuccess = true
				}
			case int:
				if v == 0 {
					isSuccess = true
				}
			case string:
				if v == "0" {
					isSuccess = true
				}
			}

			if !isSuccess {
				lastErr = fmt.Errorf("业务请求失败：code=%v", codeVal)
				msg := result["msg"]
				logger.Warnf("业务状态码非 0 (尝试 %d/%d): code=%v, msg=%v", attempt, maxRetries, codeVal, msg)

				if attempt < maxRetries {
					time.Sleep(1 * time.Second)
					continue
				}
				// 重试耗尽仍失败，返回结果和错误，方便调用方获取详细错误信息
				return result, lastErr
			}
		}

		// 成功
		logger.Debugf("响应数据：%+v", result)
		return result, nil
	}

	return nil, fmt.Errorf("未知错误：重试循环结束但未返回结果")
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

// 辅助函数：获取interface{}的长度（如果可能）
func getLength(v interface{}) interface{} {
	switch arr := v.(type) {
	case []interface{}:
		return len(arr)
	case []map[string]interface{}:
		return len(arr)
	default:
		return "unknown"
	}
}

func SendRequest2[T any](method, url string, header map[string]string, params interface{}, skipTLSVerify bool, respObj *T) error {
	// 1. 序列化请求参数（仅一次，避免冗余）
	reqBody, err := json.Marshal(params)
	if err != nil {
		log.Printf("[ERROR] 请求参数JSON序列化失败: %v", err)
		return fmt.Errorf("请求参数序列化失败: %w", err)
	}
	// 打印请求详情（便于排查）
	log.Printf("[DEBUG] 发送HTTP请求: method=%s, url=%s, header=%+v, params=%s",
		method, url, header, string(reqBody))

	// 2. 配置HTTP客户端（修复安全隐患：让调用者决定是否跳过TLS验证）
	client := &http.Client{}
	if skipTLSVerify {
		log.Println("[WARNING] 已跳过TLS证书验证！生产环境禁止使用，存在安全风险！")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// 3. 创建HTTP请求
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("[ERROR] 创建HTTP请求失败: %v", err)
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 4. 设置请求头（默认JSON类型，支持自定义头）
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	for k, v := range header {
		req.Header.Set(k, v)
	}

	// 5. 发送请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] 发送HTTP请求失败: %v", err)
		return fmt.Errorf("发送请求失败: %w", err)
	}

	// 1. 读取响应体一次
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] 读取HTTP响应体失败: %v", err)
		return fmt.Errorf("读取响应体失败: %w", err)
	}
	defer resp.Body.Close()

	// 2. 校验HTTP响应状态码
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[ERROR] HTTP响应状态码异常: code=%d, body=%s", resp.StatusCode, string(respBody))
		return fmt.Errorf("HTTP响应错误: 状态码=%d, 响应体=%s", resp.StatusCode, string(respBody))
	}

	// 3. 强类型解析响应体
	if err := json.Unmarshal(respBody, respObj); err != nil {
		log.Printf("[ERROR] 响应体JSON解析失败: err=%v, body=%s", err, string(respBody))
		return fmt.Errorf("响应体解析失败: %w (原始响应: %s)", err, string(respBody))
	}

	return nil
}

func GetRequest[T any](method, urlStr string, header map[string]string, params map[string]interface{}, skipTLSVerify bool, respObj *T) error {
	// 1. 处理请求参数：GET拼URL查询串，POST序列化请求体
	var (
		reqBody io.Reader // 请求体（GET为nil，POST为JSON字节流）
		err     error
	)

	// 1.1 GET请求：参数转为URL查询字符串
	if strings.ToUpper(method) == http.MethodGet {
		// 将params（map/结构体）转为url.Values（自动URL编码）
		queryParams, err := paramsToURLValues(params)
		if err != nil {
			log.Printf("[ERROR] GET参数转换失败: %v", err)
			return fmt.Errorf("GET参数转换失败: %w", err)
		}
		// 拼接URL和查询字符串（处理原始URL已有query的情况，如"xxx?a=1" -> "xxx?a=1&b=2"）
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			log.Printf("[ERROR] 解析URL失败: %v", err)
			return fmt.Errorf("解析URL失败: %w", err)
		}
		// 合并查询参数（原始URL的query + 新参数）
		parsedURL.RawQuery = queryParams.Encode()
		urlStr = parsedURL.String() // 更新为带查询参数的URL
		log.Printf("[DEBUG] GET请求URL（含参数）: %s", urlStr)
	}

	// 1.2 POST请求：参数序列化为JSON请求体（保留原逻辑）
	if strings.ToUpper(method) == http.MethodPost {
		reqBodyBytes, err := json.Marshal(params)
		if err != nil {
			log.Printf("[ERROR] POST参数序列化失败: %v", err)
			return fmt.Errorf("POST参数序列化失败: %w", err)
		}
		reqBody = bytes.NewBuffer(reqBodyBytes)
		log.Printf("[DEBUG] POST请求体: %s", string(reqBodyBytes))
	}

	// 2. 配置HTTP客户端（保留TLS安全提醒）
	client := &http.Client{}
	if skipTLSVerify {
		log.Println("[WARNING] 已跳过TLS证书验证！生产环境禁止使用，存在安全风险！")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// 3. 创建HTTP请求
	req, err := http.NewRequest(strings.ToUpper(method), urlStr, reqBody)
	if err != nil {
		log.Printf("[ERROR] 创建请求失败: %v", err)
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 4. 设置请求头：GET自动移除Content-Type（无请求体，无需该头）
	if strings.ToUpper(method) == http.MethodPost {
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	}
	// 合并自定义请求头
	for k, v := range header {
		req.Header.Set(k, v)
	}

	// 5. 发送请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] 发送请求失败: %v", err)
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 6. 校验HTTP状态码（保留原逻辑，避免忽略404/500）
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(resp.Body)
		log.Printf("[ERROR] HTTP状态码异常: code=%d, body=%s", resp.StatusCode, string(errBody))
		return fmt.Errorf("HTTP响应错误: 状态码=%d, 响应体=%s", resp.StatusCode, string(errBody))
	}

	// 7. 完整读取响应体（缓存原始数据，避免解析异常）
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] 读取响应体失败: %v", err)
		return fmt.Errorf("读取响应体失败: %w", err)
	}
	rawRespBody := string(respBodyBytes)
	log.Printf("[DEBUG] 服务器原始响应体: %s", rawRespBody)

	// 8. 强类型解析响应体（与POST逻辑一致，确保嵌套数组正常解析）
	if err := json.Unmarshal(respBodyBytes, respObj); err != nil {
		log.Printf("[ERROR] 响应体解析失败: err=%v, 原始响应=%s", err, rawRespBody)
		return fmt.Errorf("响应体解析失败: %w (原始响应: %s)", err, rawRespBody)
	}

	return nil
}

// paramsToURLValues 将参数（map/结构体）转为url.Values（支持URL编码）
// 支持的参数类型：
//  1. map[string]interface{}（值支持int/string/bool等基础类型）
//  2. 结构体（通过tag `url:"key"` 指定查询参数名，无tag则用字段名）
func paramsToURLValues(params interface{}) (url.Values, error) {
	values := url.Values{}
	if params == nil {
		return values, nil
	}

	// 处理map类型（如map[string]interface{}{"page":1, "limit":20}）
	if m, ok := params.(map[string]interface{}); ok {
		for key, val := range m {
			values.Add(key, toString(val))
		}
		return values, nil
	}

	// 处理结构体类型（如struct{ Page int `url:"page"`; Limit int `url:"limit"` }）
	val := reflect.ValueOf(params)
	// 若为指针，取指向的值
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	// 仅支持结构体类型
	if val.Kind() != reflect.Struct {
		return values, fmt.Errorf("不支持的参数类型: %T（仅支持map和结构体）", params)
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldVal := val.Field(i)

		// 跳过未导出字段（首字母小写）
		if field.PkgPath != "" {
			continue
		}

		// 获取查询参数名：优先用tag `url:"key"`，无tag则用字段名（首字母小写）
		paramKey := field.Tag.Get("url")
		if paramKey == "" {
			// 字段名首字母小写（如Page -> page）
			paramKey = strings.ToLower(field.Name[:1]) + field.Name[1:]
		}
		// 跳过tag为`url:"-"`的字段（忽略该字段）
		if paramKey == "-" {
			continue
		}

		// 将字段值转为字符串
		values.Add(paramKey, toString(fieldVal.Interface()))
	}

	return values, nil
}

// toString 将基础类型（int/string/bool等）转为字符串
func toString(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case string:
		return val
	case bool:
		return strconv.FormatBool(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		// 其他类型默认转为JSON字符串（避免类型丢失）
		b, _ := json.Marshal(val)
		return string(b)
	}
}
