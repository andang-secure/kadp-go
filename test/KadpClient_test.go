package test

import (
	"fmt"
	"github.com/andang-security/kadp-go/algorithm"
	"github.com/andang-security/kadp-go/encryption"
	"github.com/andang-security/kadp-go/mode"
	"github.com/andang-security/kadp-go/padding"
	"log"
	"testing"
)

func TestAdd(t *testing.T) {

	url := "https://192.168.0.130:10060"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEF4ujA8UNuXIMi2PdptjHdhEB0Qlz5G6AbCAexXDhKJyET8IuRNyWQ9OjVmI59OmRdKlzNANAcoqNShrUQIppTRNf9YpB7bjFeprmHH0IqwDZi26QnFD+nYCrztHIr1sloKDBle6a6bjl5V0pl3psUkq81XPBvPYRmePABplQqOQObQq0+Wa7ftBGQefsODWf5CgEsGRUoePltKLRtHWiTUdDdm7v0bJljuhhzjlLKHajQLUnxq3Wi5BaMp39JOg3j8Fji/UhXSbi+XtUKLWQiepYjqQa7e1LONYpgkhX7V34HirVvaoTsw+sRhcR1ol0g=="
	myClient := encryption.NewKADPClient(url, token)

	encrypt, err := myClient.FpeEncipher("151918123", algorithm.FF3, "12345678", 36, 16, "kadp112", 2, 6)
	if err != nil {
		fmt.Println(err)
	}
	log.Println(encrypt)

	fmt.Println("密文" + encrypt)
	asdas := "asd密文"
	decipher, err := myClient.FpeDecipher(encrypt, algorithm.FF3, "12345678", 36, 16, "kadp112", 2, 6)
	fmt.Println(decipher)

	encipher, err := myClient.Encipher([]byte(asdas), algorithm.AES, mode.CBC, padding.NoPadding, 16, "kadp11211", "1234567897894561")
	if err != nil {
		return
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, algorithm.AES, mode.CBC, padding.NoPadding, 16, "kadp11211", "1234567897894561")
	fmt.Println(plaintext)

	if err != nil {
		return
	}
	fmt.Println("解密" + decipher)
	log.Println(decipher)

}
