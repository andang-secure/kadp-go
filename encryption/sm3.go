package encryption

import (
	"encoding/base64"
	"github.com/tjfoc/gmsm/sm3"
)

type sm3Cipher struct {
	key string
	iv  string
}

func newSm3Cipher(key string, iv string) sm3Cipher {
	return sm3Cipher{key: key, iv: iv}
}

func (s *sm3Cipher) Sm3Encrypt(plaintext []byte) (string, error) {
	cipherText := sm3.Sm3Sum(plaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(cipherText)

	return cipherTextBase64, nil
}
