package encryption

import (
	"encoding/base64"
	"github.com/tjfoc/gmsm/sm4"
)

func sm4CbcEncrypt(plaintext, key []byte) (string, error) {
	cipherText, err := sm4.Sm4Cbc(key, plaintext, true)

	if err != nil {
		return "", err
	}

	cipherTextBase64 := base64.StdEncoding.EncodeToString(cipherText)
	return cipherTextBase64, nil
}

func sm4CbcDecrypt(plaintext string, key []byte) (string, error) {

	plaintextDecode, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return "", err
	}
	cipherText, err := sm4.Sm4Cbc(key, plaintextDecode, true)

	if err != nil {
		return "", err
	}

	cipherTextBase64 := base64.StdEncoding.EncodeToString(cipherText)
	return cipherTextBase64, nil
}
