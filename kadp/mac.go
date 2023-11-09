package kadp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	logger "github.com/sirupsen/logrus"
)

func generateHMAC(key []byte, message []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	hashed := h.Sum(nil)

	hexHash := base64.StdEncoding.EncodeToString(hashed)
	return hexHash
}

func verifyIntegrity(key []byte, message []byte, receivedHMAC string) (bool, error) {
	// 生成接收到的消息的HMAC值
	computedHMAC := generateHMAC(key, message)
	logger.Debug(computedHMAC)
	logger.Debug(receivedHMAC)

	receivedHMACdecode, err := base64.StdEncoding.DecodeString(receivedHMAC)
	if err != nil {
		return false, errors.New("base64 decode fail")
	}

	computedHMACdecode, err := base64.StdEncoding.DecodeString(computedHMAC)
	if err != nil {
		return false, errors.New("base64 decode fail")
	}

	return hmac.Equal(computedHMACdecode, receivedHMACdecode), nil
}
