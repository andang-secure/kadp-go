package test

import (
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/kadp"
	logger "github.com/sirupsen/logrus"
	"testing"
)

func TestKadp(t *testing.T) {

	//url := "https://127.0.0.1:8090"
	//token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKesS0JhbLLai/aJeKzdyq79J9VrY9WrZIb9CbEm4Ivsoi23z/8h+ZpNbPnRSrQcDp5Ad7EXJR30thzPxt9vzRTjElJ0bqppU9TQJDgRqKcF3Zx0nx2fynzTZabN/EKSbcw=="
	//myClient, err := kadp.NewKADPClient(url, token, "QVSxoBH+SsUH9Vl3UC3D7YGV4tw5vaI7T/joivh/7FECvH06rcTwJvHjxvzdy8cD", "keystore.jks", "123456")

	logger.SetLevel(logger.DebugLevel)
	url := "http://192.168.0.129:8190"
	RegisterToken := "hnludUczLOwZfj0t84j1Eh0btPVNviLgPSjOfuS8oKaNNLACoKUd56YNb31jzU+d"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKUtx/89hfUahPcUD5H9hreRPVpFvEk/XV3yV3B3OhI2N1Lpops2R20qfdl/2VfKbhIklvHWEL1UoWmGUII6G4jOTr0FZoKOXwnlvasbTdkiFGgGI+EUgbgYh4+r8Z875ADNEF+Uwae1UWKHs7Brrf9pB/bvkrWJIr4q1bduMYMLb3sYjkjchlyfwd+5WIESIcAmQaB1V5ChLDSMOXudqAh9jnuibzNGkBjAcwMRTB+K0b5mTkwyXIJTUSIIHvco8IZLVoPWGrDX/nEamGuzqbGE="
	myClient, err := kadp.NewKADPClient(&configs.KmsConfig{
		Domain:           url,
		Credential:       token,
		RegisterToken:    RegisterToken,
		KeystoreFileName: "keystore1.jks",
		KeystorePassword: "123456",
	})
	if err != nil {
		t.Error(err)
		return
	}

	//url := "https://192.168.0.135:8390"
	//token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEP/z+clh1zM1fMnHmIVmepiB8y6IQC2GTmUVA7bfhfsbreTWy59jhDOQ+EnFLSau0R4NOLZv7ZopZZ88B5KuIde6HR7h4NvY4Rm8xrSVb17K/YfoYS59P4LOBzMjB4aSk74Z7C5Kk1nCosQBN7LH6eBewZKUAquBi4iXtw3MNpR+SCOoJKzZiWFWPyffmsb9MLpEWC7+VqzFdiPMsvA781aO1LbuU4UA/VpOzwoXIVuw8UskLbjhLNOG0ot6mHUKjiohmxGtYAmnac/ylx8/Fus6n69HzGCxdpm/406VnPz1eiCQvW5Zc8CNrcBeZQCdutCFCxNyNmPBm4e0t8pcqqjxeDacaWMCLnp8cvPKalQppcpVCVOGqHjhLTKbRoCOzPbR9X3I7GBii3gEbQg3Fqb6pTSLSyG9+8vlauD11amb"
	//myClient, err := kadp.NewKADPClient(url, token, "Fps7T/jRIevtJih8GVcp02HmTWRIis//Fqd8LbbiOaPYI0tcSI1mCeh7ecInQC77", "keystore.jks", "123456")

	label := "throughput-test-wd2cs"
	_, err = myClient.CreateCipherKey(16, label, 1)
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println("密钥创建成功")
	//FPE
	str := "15191812322"
	tweak := "1234567"
	alphabet := "0123456789"
	start := 0
	end := 8
	encrypt, err := myClient.FpeEncipher(&kadp.FpeEncipherRequest{
		Plaintext: str,
		Fpe:       kadp.FF1,
		Tweak:     tweak,
		Alphabet:  alphabet,
		Label:     label,
		Start:     start,
		End:       end,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("FPE密文：" + encrypt)

	decipher, err := myClient.FpeDecipher(&kadp.FpeDecipherRequest{
		Ciphertext: encrypt,
		Fpe:        kadp.FF1,
		Tweak:      tweak,
		Alphabet:   alphabet,
		Label:      label,
		Start:      start,
		End:        end,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("FPE明文：" + decipher)

	//AES
	data := "1234567891234567"
	iv := "1234567891234567"
	encipher, err := myClient.Encipher(&kadp.EncipherRequest{
		Plaintext: []byte(data),
		//CipherKey: key,
		Algorithm: kadp.SM4,
		Mode:      kadp.ECB,
		Padding:   kadp.NoPadding,
		Label:     label,
		IV:        iv,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(&kadp.DecryptRequest{
		Ciphertext: encipher,
		//CipherKey:  key,
		Algorithm: kadp.SM4,
		Mode:      kadp.ECB,
		Padding:   kadp.NoPadding,
		Label:     label,
		IV:        iv,
	})

	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("解密", string(plaintext))

	//非对称加解密
	pub, pri, err := myClient.AsymmetricKeyPair(kadp.SM2)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("公钥：", pub)
	fmt.Println("私钥：", pri)

	publicEncrypt, err := myClient.AsymmetricEncrypt(&kadp.AsymmetricEncryptRequest{
		Plaintext: data,
		Algorithm: kadp.SM2,
		PublicKey: pub,
	})

	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("非对称加密密文：", publicEncrypt)

	decrypt, err := myClient.AsymmetricDecrypt(&kadp.AsymmetricDecryptRequest{
		Ciphertext: publicEncrypt,
		Algorithm:  kadp.SM2,
		PrivateKey: pri,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("私钥解密：", decrypt)

	//签名验签
	uid := []byte("1")
	r, s, err := myClient.SM2Sign(&kadp.SM2SignRequest{
		Plaintext:  data,
		PrivateKey: pri,
		Uid:        uid,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("签名:", r, s)

	verify, err := myClient.SM2Verify(&kadp.SM2VerifyRequest{
		Plaintext: data,
		PublicKey: pub,
		R:         r,
		S:         s,
		Uid:       uid,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("验签:", verify)

	//sha256
	Hash := myClient.DigestEncrypt(data)
	fmt.Println("摘要哈希：", Hash)

	hash, err := myClient.Hmac(&kadp.HmacRequest{
		Message: []byte(data),
		Label:   label,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("Hmac值：", hash)

	hmacVerify, err := myClient.HmacVerify(&kadp.HmacVerifyRequest{
		Message: []byte(data),
		Label:   label,
		HmacVal: hash,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("验证Hmac成功：", hmacVerify)

	SHA1Val, err := myClient.SHASum([]byte(data), kadp.Sha1)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("SHA1计算：", SHA1Val)

	SHA256Val, err := myClient.SHASum([]byte(data), kadp.Sha256)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("SHA256计算：", SHA256Val)

	list, err := myClient.KeyManager.SecretKeyList(&kadp.KeyListParam{
		Page:     "1",
		PageSize: "10",
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("密钥列表：", list)

	id, err := myClient.KeyManager.CreateKey(&kadp.CreateKeyRequest{
		Name:      "kadp-test-1123x3",
		Algorithm: 4,
		Size:      128,
		KeyUsage:  "3",
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("密钥创建：", id)

	keyInfo, err := myClient.KeyManager.GetKeyInfo(id)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("密钥信息：", keyInfo)

	err = myClient.KeyManager.UpdateKey(&kadp.UpdateKeyRequest{
		Id:         id,
		Deletable:  1,
		Exportable: 0,
		KeyUsage:   "1",
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("密钥修改：")

	err = myClient.KeyManager.DeleteKey(id)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("密钥删除：")
	//
	//err = myClient.KeyManager.AddKeyVersion(id)
	//if err != nil {
	//	t.Error(err)
	//	return
	//}
	//fmt.Println("版本添加：")

	//err = myClient.KeyManager.CloneKey(&kadp.CloneKeyRequest{
	//	Id:   id,
	//	Name: "das",
	//})
	//if err != nil {
	//	t.Error(err)
	//	return
	//}
	fmt.Println("密钥克隆：")
	keyExportData, err := myClient.KeyManager.ExportKey(&kadp.ExportKeyRequest{
		KeyName:    "kadp-test-1123-pub",
		KeyVersion: 0,
	})
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("密钥导出：", keyExportData)
}
