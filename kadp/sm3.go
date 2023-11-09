package kadp

import (
	"encoding/base64"
	"github.com/tjfoc/gmsm/sm3"
)

func sm3Encrypt(plaintext []byte) string {
	cipherText := sm3.Sm3Sum(plaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(cipherText)

	return cipherTextBase64
}
