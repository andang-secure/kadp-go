package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {

	domain := "https://192.168.0.135:8390"
	appKey := "adc17d7141c6e02c09d917a56559102ec4"
	appSecret := "2dfc48d7da9488b4597d050f24785780"
	registerToken := "TxfzmhSA+q7yw6Fd9w63PA4FiJm+iii5/FyEzGyOrjSz3N7KOsfYvNLUQDuEOTLX"
	label := "sq02"

	//domain := "https://192.168.0.192"
	////cj
	//appKey := "ad6612922dbdc2169b31be8c22f28350fa"
	//appSecret := "b0e6d63f978418e0da4214912ddd4a9f"
	//label := "df"
	keyStoreFileName := "sdk-keystore.jks"

	client, err := kadp.NewSMSClient(domain, appKey, appSecret, keyStoreFileName, "", registerToken)
	if err != nil {
		fmt.Printf("Failed to create SMSClient: %v", err)
		return
	}

	if client == nil {
		fmt.Printf("SMSClient is nil")
		return
	}

	str, err := client.GetSmsCipherText(label)
	if err != nil {
		fmt.Printf("getSmsCipherText failed: %v", err)
		return
	}
	fmt.Println("str", str)
}
