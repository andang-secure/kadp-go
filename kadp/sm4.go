package kadp

import (
	"encoding/base64"
	"github.com/tjfoc/gmsm/sm4"
)

func sm4CbcEncrypt(plaintext []byte, key string) (string, error) {

	decodeKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	cipherText, err := sm4.Sm4Cbc(decodeKey, plaintext, true)

	if err != nil {
		return "", err
	}
	cipherTextBase64 := base64.StdEncoding.EncodeToString(cipherText)
	return cipherTextBase64, nil
}

func sm4CbcDecrypt(ciphertext, key string) (string, error) {

	decodeKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	ciphertextDecode, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext, err := sm4.Sm4Cbc(decodeKey, ciphertextDecode, false)

	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
