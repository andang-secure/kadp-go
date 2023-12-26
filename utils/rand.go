package utils

import (
	"crypto/rand"
	"fmt"
)

func GenerateRandom() ([]byte, error) {
	// 定义要生成的随机字节数
	byteCount := 32

	// 生成两个随机字节数组
	randomBytes1 := make([]byte, byteCount)

	_, err := rand.Read(randomBytes1)
	if err != nil {
		fmt.Println("无法生成随机数1:", err)
		return nil, err
	}
	return randomBytes1, nil
}

// XorBytes 异或两个字节数组
func XorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}
