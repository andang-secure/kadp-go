package test

import (
	"fmt"
	"github.com/andang-security/kadp/encryption"
	"testing"
)

func TestAdd(t *testing.T) {

	url := "https://www.ksp.com"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEBICTP6x6VoLVESzQ80mwJP/PJbzRMLjLpEfeiSTwbk9Kl/ZVx9UYdy78KHKi3qfOOQEbvmWjpO2fUIf5su2d6TYl18iViwrM8k2Upx8Rf8zwfBieVaWvQrasBO6wOCRjKFnNjimzg1pfzhiYlgtNZlwNB2klatVst0IXkUO20kY1TLFV5goXXptLnAnGZZxmGawzrJ1pI7cwiPVBN6L37ss0l+RAY6EN/iT236ikXipIeQXNIBfpMPTDGUA0wGb7dygrl5FHw3FYUyoA1aLgmnOjY9GBEH/N7OUsquYmdA67OXyS79QAqad+uVe5MsxHWpf0VNaqd9a5fKzqapqiuk="
	myClient := encryption.NewKADPClient(url, token)
	myClient.GetDekCipherText("kadp", 16)
	fmt.Println(myClient)
	encrypt, err := myClient.FpeEncipher("1329959757", encryption.FF1, 10, 16, "kadp")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("密文" + encrypt)
	decipher, err := myClient.FpeDecipher(encrypt, encryption.FF1, 10, 16, "kadp")
	if err != nil {
		return
	}
	fmt.Println("解密" + decipher)

}
