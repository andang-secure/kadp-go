package kadp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/tjfoc/gmsm/sm4"
	"io"
)

// aseCbcNoPadEncrypt 使用AES-CBC/NoPadding模式加密数据
func aseCbcNoPadEncrypt(req *EncipherRequest, key []byte) (string, error) {

	var (
		block cipher.Block
		err   error
	)
	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(req.Plaintext))

	mode := cipher.NewCBCEncrypter(block, []byte(req.IV))
	mode.CryptBlocks(ciphertext, req.Plaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return cipherTextBase64, nil
}

// aseCbcNoPadDecrypt  使用AES-CBC/NoPadding模式解密数据
func aseCbcNoPadDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {
	textByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var (
		block cipher.Block
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}

	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(textByte))

	mode := cipher.NewCBCDecrypter(block, []byte(req.IV))
	mode.CryptBlocks(plaintext, textByte)

	return plaintext, nil
}

// aseCbcPaddingEncrypt 使用AES-CBC/PKCS5Padding模式加密数据
func aseCbcPaddingEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)
	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}

	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	switch req.Padding {
	case PKCS5Padding:
		req.Plaintext = pKCS5Padding(req.Plaintext, blockSize)
	case PKCS7Padding:
		req.Plaintext, err = pKCS7Padding(req.Plaintext, blockSize)
		if err != nil {
			return "", err
		}
	case ISO10126Padding:
		req.Plaintext = iSO10126Padding(req.Plaintext)
	case ZeroPadding:
		req.Plaintext = zeroPadding(req.Plaintext, blockSize)
	}

	blockMode := cipher.NewCBCEncrypter(block, []byte(req.IV))
	ciphertext := make([]byte, len(req.Plaintext))
	blockMode.CryptBlocks(ciphertext, req.Plaintext)
	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return cipherTextBase64, nil
}

// aseCbcPaddingDecrypt 使用AES-CBC/PKCS5Padding模式解密数据
func aseCbcPaddingDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {
	textByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, []byte(req.IV))
	origData := make([]byte, len(textByte))
	blockMode.CryptBlocks(origData, textByte)
	switch req.Padding {
	case PKCS5Padding:
		origData = pKCS5UnPadding(origData)
	case PKCS7Padding:
		origData, err = pKCS7UnPadding(origData)
		if err != nil {
			return nil, err
		}
	case ISO10126Padding:
		origData = iSO10126UnPadding(origData)
	case ZeroPadding:
		origData = zeroUnPadding(origData)
	}

	return origData, nil
}

// aesCtrNoPadEncrypt 使用AES-CTR/PKCS5Encrypt模式加密数据
func aesCtrNoPadEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, []byte(req.IV))
	//3. 加密

	dst := make([]byte, len(req.Plaintext))
	stream.XORKeyStream(dst, req.Plaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(dst)

	return cipherTextBase64, nil
}

// aesCtrNoPadDecrypt 使用AES-CTR/NoPadding模式解密数据
func aesCtrNoPadDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {

	cipherTextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}
	//2. 创建分组模式，在crypto/cipher包中
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, []byte(req.IV))
	//3. 加密
	dst := make([]byte, len(cipherTextByte))
	stream.XORKeyStream(dst, cipherTextByte)

	return dst, nil
}

func aesCtrPaddingEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)
	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	switch req.Padding {
	case PKCS5Padding:
		req.Plaintext = pKCS5Padding(req.Plaintext, blockSize)
	case PKCS7Padding:
		req.Plaintext, err = pKCS7Padding(req.Plaintext, blockSize)
		if err != nil {
			return "", err
		}
	case ISO10126Padding:
		req.Plaintext = iSO10126Padding(req.Plaintext)
	case ZeroPadding:
		req.Plaintext = zeroPadding(req.Plaintext, blockSize)
	}
	//2. 创建分组模式
	stream := cipher.NewCTR(block, []byte(req.IV))
	//3. 加密

	dst := make([]byte, len(req.Plaintext))
	stream.XORKeyStream(dst, req.Plaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(dst)

	return cipherTextBase64, nil
}

// aesCtrPK5PadDecrypt 使用AES-CTR/NoPadding模式解密数据
func aesCtrPaddingDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {

	cipherTextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}

	//2. 创建分组模式，在crypto/cipher包中
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, []byte(req.IV))
	//3. 加密
	dst := make([]byte, len(cipherTextByte))
	stream.XORKeyStream(dst, cipherTextByte)

	switch req.Padding {
	case PKCS5Padding:
		dst = pKCS5UnPadding(dst)
	case PKCS7Padding:
		dst, err = pKCS7UnPadding(dst)
		if err != nil {
			return nil, err
		}
	case ISO10126Padding:
		dst = iSO10126UnPadding(dst)
	case ZeroPadding:
		dst = zeroUnPadding(dst)
	}

	return dst, nil
}

// aesEcbNoPadEncrypt 使用ECB模式进行AES加密
func aesEcbNoPadEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)
	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	ciphertext := make([]byte, len(req.Plaintext))

	// 分组加密
	for i := 0; i < len(req.Plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], req.Plaintext[i:i+blockSize])
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return ciphertextBase64, nil
}

// aesEcbNoPadDecrypt 使用ECB模式进行AES解密
func aesEcbNoPadDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext := make([]byte, len(ciphertextByte))

	// 分组解密
	for i := 0; i < len(ciphertextByte); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertextByte[i:i+blockSize])
	}

	return plaintext, nil
}

// 使用ECB模式进行AES加密
func aesEcbPaddingEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	switch req.Padding {
	case PKCS5Padding:
		req.Plaintext = pKCS5Padding(req.Plaintext, blockSize)
	case PKCS7Padding:
		req.Plaintext, err = pKCS7Padding(req.Plaintext, blockSize)
		if err != nil {
			return "", err
		}
	case ISO10126Padding:
		req.Plaintext = iSO10126Padding(req.Plaintext)
	case ZeroPadding:
		req.Plaintext = zeroPadding(req.Plaintext, blockSize)
	}

	ciphertext := make([]byte, len(req.Plaintext))

	// 分组加密
	for i := 0; i < len(req.Plaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], req.Plaintext[i:i+block.BlockSize()])
	}
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return ciphertextBase64, nil
}

// 使用ECB模式进行AES解密
func aesEcbPaddingDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertextByte))

	// 分组解密
	for i := 0; i < len(ciphertextByte); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertextByte[i:i+block.BlockSize()])
	}

	switch req.Padding {
	case PKCS5Padding:
		plaintext = pKCS5UnPadding(plaintext)
	case PKCS7Padding:
		plaintext, err = pKCS7UnPadding(plaintext)
		if err != nil {
			return nil, err
		}
	case ISO10126Padding:
		plaintext = iSO10126UnPadding(plaintext)
	case ZeroPadding:
		plaintext = zeroUnPadding(plaintext)
	}

	return plaintext, nil
}

func aesCfbNoPadEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)
	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(req.Plaintext))
	stream := cipher.NewCFBEncrypter(block, []byte(req.IV))
	stream.XORKeyStream(ciphertext, req.Plaintext)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesCfbNoPadDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {
	ciphertextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block
	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewCFBDecrypter(block, []byte(req.IV))
	stream.XORKeyStream(plainText, ciphertextByte)

	return plainText, nil
}

func aesCfbPaddingEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	switch req.Padding {
	case PKCS5Padding:
		req.Plaintext = pKCS5Padding(req.Plaintext, blockSize)
	case PKCS7Padding:
		req.Plaintext, err = pKCS7Padding(req.Plaintext, blockSize)
		if err != nil {
			return "", err
		}
	case ISO10126Padding:
		req.Plaintext = iSO10126Padding(req.Plaintext)
	case ZeroPadding:
		req.Plaintext = zeroPadding(req.Plaintext, blockSize)
	}

	ciphertext := make([]byte, len(req.Plaintext))
	stream := cipher.NewCFBEncrypter(block, []byte(req.IV))
	stream.XORKeyStream(ciphertext, req.Plaintext)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesCfbPaddingDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {
	ciphertextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewCFBDecrypter(block, []byte(req.IV))
	stream.XORKeyStream(plainText, ciphertextByte)

	switch req.Padding {
	case PKCS5Padding:
		plainText = pKCS5UnPadding(plainText)
	case PKCS7Padding:
		plainText, err = pKCS7UnPadding(plainText)
		if err != nil {
			return nil, err
		}
	case ISO10126Padding:
		plainText = iSO10126UnPadding(plainText)
	case ZeroPadding:
		plainText = zeroUnPadding(plainText)
	}

	return plainText, nil
}

func aesOfbNoPadEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(req.Plaintext))
	stream := cipher.NewOFB(block, []byte(req.IV))
	stream.XORKeyStream(ciphertext, req.Plaintext)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesOfbNoPadDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewOFB(block, []byte(req.IV))
	stream.XORKeyStream(plainText, ciphertextByte)

	return plainText, nil
}

func aesOfbPaddingEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	switch req.Padding {
	case PKCS5Padding:
		req.Plaintext = pKCS5Padding(req.Plaintext, blockSize)
	case PKCS7Padding:
		req.Plaintext, err = pKCS7Padding(req.Plaintext, blockSize)
		if err != nil {
			return "", err
		}
	case ISO10126Padding:
		req.Plaintext = iSO10126Padding(req.Plaintext)
	case ZeroPadding:
		req.Plaintext = zeroPadding(req.Plaintext, blockSize)
	}

	ciphertext := make([]byte, len(req.Plaintext))
	stream := cipher.NewOFB(block, []byte(req.IV))
	stream.XORKeyStream(ciphertext, req.Plaintext)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesOfbPaddingDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewOFB(block, []byte(req.IV))
	stream.XORKeyStream(plainText, ciphertextByte)

	switch req.Padding {
	case PKCS5Padding:
		plainText = pKCS5UnPadding(plainText)
	case PKCS7Padding:
		plainText, err = pKCS7UnPadding(plainText)
		if err != nil {
			return nil, err
		}
	case ISO10126Padding:
		plainText = iSO10126UnPadding(plainText)
	case ZeroPadding:
		plainText = zeroUnPadding(plainText)
	}

	return plainText, nil
}

func aesGcmNoPadEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, req.Plaintext, nil)
	ciphertext = append(nonce, ciphertext...)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesGcmNoPadDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {
	ciphertextBase64, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}

	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertextBase64) < nonceSize {
		return nil, fmt.Errorf("密文长度不正确")
	}

	nonce := ciphertextBase64[:nonceSize]
	ciphertextBase64 = ciphertextBase64[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBase64, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func aesGcmPaddingEncrypt(req *EncipherRequest, key []byte) (string, error) {
	var (
		block cipher.Block
		err   error
	)

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}

	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	switch req.Padding {
	case PKCS5Padding:
		req.Plaintext = pKCS5Padding(req.Plaintext, blockSize)
	case PKCS7Padding:
		req.Plaintext, err = pKCS7Padding(req.Plaintext, blockSize)
		if err != nil {
			return "", err
		}
	case ISO10126Padding:
		req.Plaintext = iSO10126Padding(req.Plaintext)
	case ZeroPadding:
		req.Plaintext = zeroPadding(req.Plaintext, blockSize)
	}

	ciphertext := aesGCM.Seal(nil, nonce, req.Plaintext, nil)
	ciphertext = append(nonce, ciphertext...)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesGcmPaddingDecrypt(req *DecryptRequest, key []byte) ([]byte, error) {
	ciphertextBase64, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch req.Algorithm {
	case AES:
		block, err = aes.NewCipher(key)
	case SM4:
		block, err = sm4.NewCipher(key)
	case DES:
		block, err = des.NewTripleDESCipher(key)
	}

	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertextBase64) < nonceSize {
		return nil, fmt.Errorf("密文长度不正确")
	}

	nonce := ciphertextBase64[:nonceSize]
	ciphertextBase64 = ciphertextBase64[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, ciphertextBase64, nil)
	if err != nil {
		return nil, err
	}
	switch req.Padding {
	case PKCS5Padding:
		plainText = pKCS5UnPadding(plainText)
	case PKCS7Padding:
		plainText, err = pKCS7UnPadding(plainText)
		if err != nil {
			return nil, err
		}
	case ISO10126Padding:
		plainText = iSO10126UnPadding(plainText)
	case ZeroPadding:
		plainText = zeroUnPadding(plainText)
	}

	return plainText, nil
}

func pKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

// PKCS7补全
func pKCS7Padding(plaintext []byte, blockSize int) ([]byte, error) {
	// 1. 校验块长度合法性（必须>0）
	if blockSize <= 0 {
		return nil, fmt.Errorf("无效的块长度[%d]，必须大于0", blockSize)
	}

	// 2. 计算填充长度（符合PKCS7规则：空数据填充blockSize个字节）
	padding := blockSize - len(plaintext)%blockSize

	// 3. 生成填充字节（padding个0xpadding）
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	// 4. 拼接并返回
	return append(plaintext, padText...), nil
}

// pKCS7UnPadding PKCS7解填充（生产级版本）
// 参数：
//
//	plaintext - 解密后带填充的数据集
//
// 返回：
//
//	解填充后的原始数据 + 错误（nil表示成功）
func pKCS7UnPadding(plaintext []byte) ([]byte, error) {
	// 1. 校验数据非空
	length := len(plaintext)
	if length == 0 {
		return nil, fmt.Errorf("解填充失败：数据为空")
	}

	// 2. 读取最后1字节作为填充长度
	padding := int(plaintext[length-1])

	// 3. 校验填充长度合法性（必须>0且≤数据长度）
	if padding <= 0 || padding > length {
		return nil, fmt.Errorf("解填充失败：无效的填充长度[%d]，数据长度[%d]", padding, length)
	}

	// 4. 校验所有填充字节是否合法（防数据篡改/解密错误）
	for i := length - padding; i < length; i++ {
		if int(plaintext[i]) != padding {
			return nil, fmt.Errorf("解填充失败：填充字节不合法，位置[%d]值[%d]≠填充长度[%d]", i, plaintext[i], padding)
		}
	}

	// 5. 安全截取原始数据（此时padding必然合法，不会越界）
	return plaintext[:length-padding], nil
}

func iSO10126Padding(plaintext []byte) []byte {
	// ISO10126Padding
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := make([]byte, padding-1)
	rand.Read(padtext) // you might want to check for errors here
	padtext = append(padtext, byte(padding))
	return append(plaintext, padtext...)
}

// PKCS7去除补全
func iSO10126UnPadding(paddedText []byte) []byte {
	padding := int(paddedText[len(paddedText)-1])
	if padding > len(paddedText) {
		panic("padding size is larger than the block size")
	}
	return paddedText[:len(paddedText)-padding]
}

func zeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func zeroUnPadding(origData []byte) []byte {
	return bytes.TrimRightFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}
