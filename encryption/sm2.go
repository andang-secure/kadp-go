package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
)

func sm2GenerateKey() (*sm2.PublicKey, *sm2.PrivateKey, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey // 公钥

	return publicKey, privateKey, nil
}

func sm2PubEncrypt(pubKey *sm2.PublicKey, data []byte, mode int) (string, error) {
	ciphertext, err := sm2.Encrypt(pubKey, data, rand.Reader, mode)
	if err != nil {
		return "", err
	}

	base64Ciphertext := base64.StdEncoding.EncodeToString(ciphertext)

	return base64Ciphertext, nil
}

func sm2PriDecrypt(priKey *sm2.PrivateKey, cipherText string, mode int) ([]byte, error) {
	decodeData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	ciphertext, err := sm2.Decrypt(priKey, decodeData, mode)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func sm2Sign(pri *sm2.PrivateKey, data []byte, uid []byte) (r, s *big.Int, err error) {
	sign, b, err := sm2.Sm2Sign(pri, data, uid, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return sign, b, nil
}

func sm2Verify(pub *sm2.PublicKey, data []byte, uid []byte, r, s *big.Int) bool {

	isVerify := sm2.Sm2Verify(pub, data, uid, r, s)

	return isVerify
}
