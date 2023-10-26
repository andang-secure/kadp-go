package encryption

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

func sm4CbcDecrypt(plaintext, key string) (string, error) {

	decodeKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	plaintextDecode, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return "", err
	}
	cipherText, err := sm4.Sm4Cbc(decodeKey, plaintextDecode, true)

	if err != nil {
		return "", err
	}

	cipherTextBase64 := base64.StdEncoding.EncodeToString(cipherText)
	return cipherTextBase64, nil
}
