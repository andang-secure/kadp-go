package test

import (
	"fmt"
	"github.com/andang-security/kadp-go/algorithm"
	"github.com/andang-security/kadp-go/encryption"
	"log"
	"testing"
)

func TestAdd(t *testing.T) {

	url := "https://192.168.0.190:8090"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEDpPYO1M/Hr6lfNuCmfL+Du6ijtN0EwQ4ph9Khbyk/RSj0uZTs4kQCe+Dg5Rq8zBS92LJmcxUNPJb/XKi36TIYSXjsQmmZtnkmyrC10i67uO59OF/Ea9t7AsoF78ytTjPagSJH4iI3zXYUzwhgtxwsybTlBCs1NjP3ht3VT2BvKo3HakFvinHnBseEwwTKT0HdfB0So1+6YPEikKis5ejs7Pyuh9rAIEiA0NmriDFtVvF9Hqq+wZn97ZE1n6ewCXAT0vqH8egm4KqDpxfdLME+4sy7nBU5bDG20HfYG7+7BsMb/c3+8Cq1TT8oynJbZCBg=="
	myClient := encryption.NewKADPClient(url, token)

	encrypt, err := myClient.FpeEncipher("1weqweq", algorithm.FF1, 36, 16, "kadp112")
	if err != nil {
		fmt.Println(err)
	}
	log.Println(encrypt)

	fmt.Println("密文" + encrypt)
	asdas := "asd密文"
	decipher, err := myClient.FpeDecipher(encrypt, algorithm.FF1, 32, 16, "kadp1123")
	encipher, err := myClient.Encipher([]byte(asdas), algorithm.AES, 16, "kadp11211")
	if err != nil {
		return
	}
	fmt.Println("AES密文" + encipher)

	plaintext, err := myClient.Decipher(encipher, algorithm.AES, 16, "kadp11211")
	fmt.Println(plaintext)

	if err != nil {
		return
	}
	fmt.Println("解密" + decipher)
	log.Println(decipher)

}
