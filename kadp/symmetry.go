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
func aseCbcNoPadEncrypt(plaintext, iv []byte, key string, algorithm Symmetry) (string, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return cipherTextBase64, nil
}

// aseCbcNoPadDecrypt  使用AES-CBC/NoPadding模式解密数据
func aseCbcNoPadDecrypt(ciphertext string, key string, iv []byte, algorithm Symmetry) (string, error) {
	textByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}

	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(textByte))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, textByte)

	//// 去除填充数据
	//padding := int(plaintext[len(plaintext)-1])
	//plaintext = plaintext[:len(plaintext)-padding]

	return string(plaintext), nil
}

// aseCbcPKCS5Encrypt 使用AES-CBC/PKCS5Padding模式加密数据
func aseCbcPKCS5Encrypt(plaintext, iv []byte, key string, padding Padding, algorithm Symmetry) (string, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}

	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	switch padding {
	case PKCS5Padding:
		plaintext = pKCS5Padding(plaintext, blockSize)
	case PKCS7Padding:
		plaintext = pKCS7Padding(plaintext, blockSize)
	case ISO10126Padding:
		plaintext = iSO10126Padding(plaintext)
	case ZeroPadding:
		plaintext = zeroPadding(plaintext, blockSize)
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	blockMode.CryptBlocks(ciphertext, plaintext)
	cipherTextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return cipherTextBase64, nil
}

// aseCbcPKCS5Decrypt 使用AES-CBC/PKCS5Padding模式解密数据
func aseCbcPKCS5Decrypt(ciphertext, key string, iv []byte, padding Padding, algorithm Symmetry) (string, error) {
	textByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(textByte))
	blockMode.CryptBlocks(origData, textByte)
	switch padding {
	case PKCS5Padding:
		origData = pKCS5UnPadding(origData)
	case PKCS7Padding:
		origData = pKCS7UnPadding(origData)
	case ISO10126Padding:
		origData = iSO10126UnPadding(origData)
	case ZeroPadding:
		origData = zeroUnPadding(origData)
	}

	return string(origData), nil
}

// aesCtrNoPadEncrypt 使用AES-CTR/PKCS5Encrypt模式加密数据
func aesCtrNoPadEncrypt(plainText, iv []byte, key string, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	//2. 创建分组模式，在crypto/cipher包中
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3. 加密

	dst := make([]byte, len(plainText))
	stream.XORKeyStream(dst, plainText)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(dst)

	return cipherTextBase64, nil
}

// aesCtrNoPadDecrypt 使用AES-CTR/NoPadding模式解密数据
func aesCtrNoPadDecrypt(cipherText, key string, iv []byte, algorithm Symmetry) (string, error) {

	cipherTextByte, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	//2. 创建分组模式，在crypto/cipher包中
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3. 加密
	dst := make([]byte, len(cipherTextByte))
	stream.XORKeyStream(dst, cipherTextByte)

	return string(dst), nil
}

func aesCtrPK5Encrypt(plainText, iv []byte, key string, padding Padding, algorithm Symmetry) (string, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block
	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5Padding(plainText, blockSize)
	case PKCS7Padding:
		plainText = pKCS7Padding(plainText, blockSize)
	case ISO10126Padding:
		plainText = iSO10126Padding(plainText)
	case ZeroPadding:
		plainText = zeroPadding(plainText, blockSize)
	}
	//2. 创建分组模式，在crypto/cipher包中
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3. 加密

	dst := make([]byte, len(plainText))
	stream.XORKeyStream(dst, plainText)

	cipherTextBase64 := base64.StdEncoding.EncodeToString(dst)

	return cipherTextBase64, nil
}

// aesCtrPK5PadDecrypt 使用AES-CTR/NoPadding模式解密数据
func aesCtrPK5PadDecrypt(cipherText, key string, iv []byte, padding Padding, algorithm Symmetry) (string, error) {

	cipherTextByte, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	//2. 创建分组模式，在crypto/cipher包中
	//iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)
	//3. 加密
	dst := make([]byte, len(cipherTextByte))
	stream.XORKeyStream(dst, cipherTextByte)

	switch padding {
	case PKCS5Padding:
		dst = pKCS5UnPadding(dst)
	case PKCS7Padding:
		dst = pKCS7UnPadding(dst)
	case ISO10126Padding:
		dst = iSO10126UnPadding(dst)
	case ZeroPadding:
		dst = zeroUnPadding(dst)
	}

	return string(dst), nil
}

// aesEcbNoPadEncrypt 使用ECB模式进行AES加密
func aesEcbNoPadEncrypt(plaintext []byte, key string, algorithm Symmetry) (string, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	ciphertext := make([]byte, len(plaintext))

	// 分组加密
	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
	}

	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return ciphertextBase64, nil
}

// aesEcbNoPadDecrypt 使用ECB模式进行AES解密
func aesEcbNoPadDecrypt(ciphertext, key string, algorithm Symmetry) (string, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	plaintext := make([]byte, len(ciphertextByte))

	// 分组解密
	for i := 0; i < len(ciphertextByte); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertextByte[i:i+blockSize])
	}

	return string(plaintext), nil
}

// 使用ECB模式进行AES加密
func aesEcbPKCS7PadEncrypt(plainText []byte, key string, padding Padding, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5Padding(plainText, blockSize)
	case PKCS7Padding:
		plainText = pKCS7Padding(plainText, blockSize)
	case ISO10126Padding:
		plainText = iSO10126Padding(plainText)
	case ZeroPadding:
		plainText = zeroPadding(plainText, blockSize)
	}

	ciphertext := make([]byte, len(plainText))

	// 分组加密
	for i := 0; i < len(plainText); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], plainText[i:i+block.BlockSize()])
	}
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return ciphertextBase64, nil
}

// 使用ECB模式进行AES解密
func aesEcbPKCS7PadDecrypt(ciphertext, key string, padding Padding, algorithm Symmetry) (string, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertextByte))

	// 分组解密
	for i := 0; i < len(ciphertextByte); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertextByte[i:i+block.BlockSize()])
	}

	switch padding {
	case PKCS5Padding:
		plaintext = pKCS5UnPadding(plaintext)
	case PKCS7Padding:
		plaintext = pKCS7UnPadding(plaintext)
	case ISO10126Padding:
		plaintext = iSO10126UnPadding(plaintext)
	case ZeroPadding:
		plaintext = zeroUnPadding(plaintext)
	}

	return string(plaintext), nil
}

func aesCfbNoPadEncrypt(plainText, iv []byte, key string, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainText))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plainText)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesCfbNoPadDecrypt(ciphertext, key string, iv []byte, algorithm Symmetry) (string, error) {
	ciphertextByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block
	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plainText, ciphertextByte)

	return string(plainText), nil
}

func aesCfbPKCS7PadEncrypt(plainText, iv []byte, key string, padding Padding, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5Padding(plainText, blockSize)
	case PKCS7Padding:
		plainText = pKCS7Padding(plainText, blockSize)
	case ISO10126Padding:
		plainText = iSO10126Padding(plainText)
	case ZeroPadding:
		plainText = zeroPadding(plainText, blockSize)
	}

	ciphertext := make([]byte, len(plainText))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plainText)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesCfbPKCS7PadDecrypt(ciphertext, key string, iv []byte, padding Padding, algorithm Symmetry) (string, error) {
	ciphertextByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plainText, ciphertextByte)

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5UnPadding(plainText)
	case PKCS7Padding:
		plainText = pKCS7UnPadding(plainText)
	case ISO10126Padding:
		plainText = iSO10126UnPadding(plainText)
	case ZeroPadding:
		plainText = zeroUnPadding(plainText)
	}

	return string(plainText), nil
}

func aesOfbNoPadEncrypt(plainText, iv []byte, key string, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainText))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext, plainText)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesOfbNoPadDecrypt(ciphertext, key string, iv []byte, algorithm Symmetry) (string, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(plainText, ciphertextByte)

	return string(plainText), nil
}

func aesOfbPK5PadEncrypt(plainText, iv []byte, key string, padding Padding, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5Padding(plainText, blockSize)
	case PKCS7Padding:
		plainText = pKCS7Padding(plainText, blockSize)
	case ISO10126Padding:
		plainText = iSO10126Padding(plainText)
	case ZeroPadding:
		plainText = zeroPadding(plainText, blockSize)
	}

	ciphertext := make([]byte, len(plainText))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext, plainText)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesOfbPK5PadDecrypt(ciphertext, key string, iv []byte, padding Padding, algorithm Symmetry) (string, error) {

	ciphertextByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}
	if err != nil {
		return "", err
	}

	plainText := make([]byte, len(ciphertextByte))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(plainText, ciphertextByte)

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5UnPadding(plainText)
	case PKCS7Padding:
		plainText = pKCS7UnPadding(plainText)
	case ISO10126Padding:
		plainText = iSO10126UnPadding(plainText)
	case ZeroPadding:
		plainText = zeroUnPadding(plainText)
	}

	return string(plainText), nil
}

func aesGcmNoPadEncrypt(plaintext []byte, key string, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
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

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesGcmNoPadDecrypt(ciphertext, key string, algorithm Symmetry) (string, error) {
	ciphertextBase64, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}

	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertextBase64) < nonceSize {
		return "", fmt.Errorf("密文长度不正确")
	}

	nonce := ciphertextBase64[:nonceSize]
	ciphertextBase64 = ciphertextBase64[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBase64, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func aesGcmPK5PadEncrypt(plainText []byte, key string, padding Padding, algorithm Symmetry) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
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

	switch padding {
	case PKCS5Padding:
		plainText = pKCS5Padding(plainText, blockSize)
	case PKCS7Padding:
		plainText = pKCS7Padding(plainText, blockSize)
	case ISO10126Padding:
		plainText = iSO10126Padding(plainText)
	case ZeroPadding:
		plainText = zeroPadding(plainText, blockSize)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plainText, nil)
	ciphertext = append(nonce, ciphertext...)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertextBase64, nil
}

func aesGcmPK5PadDecrypt(ciphertext, key string, padding Padding, algorithm Symmetry) (string, error) {
	ciphertextBase64, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	var block cipher.Block

	switch algorithm {
	case AES:
		block, err = aes.NewCipher(keyBytes)
	case SM4:
		block, err = sm4.NewCipher(keyBytes)
	case DES:
		block, err = des.NewTripleDESCipher(keyBytes)
	}

	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertextBase64) < nonceSize {
		return "", fmt.Errorf("密文长度不正确")
	}

	nonce := ciphertextBase64[:nonceSize]
	ciphertextBase64 = ciphertextBase64[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, ciphertextBase64, nil)
	if err != nil {
		return "", err
	}
	switch padding {
	case PKCS5Padding:
		plainText = pKCS5UnPadding(plainText)
	case PKCS7Padding:
		plainText = pKCS7UnPadding(plainText)
	case ISO10126Padding:
		plainText = iSO10126UnPadding(plainText)
	case ZeroPadding:
		plainText = zeroUnPadding(plainText)
	}

	return string(plainText), nil
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
func pKCS7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padText...)
}

// PKCS7去除补全
func pKCS7UnPadding(plaintext []byte) []byte {
	padding := int(plaintext[len(plaintext)-1])
	return plaintext[:len(plaintext)-padding]
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
