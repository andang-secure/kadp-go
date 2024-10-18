package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {
	/*
		domain := "https://192.168.0.135:8390"
		appKey := "adc17d7141c6e02c09d917a56559102ec4"
		appSecret := "2dfc48d7da9488b4597d050f24785780"
		//appKey := "ad26a46e21bd3599232a635c5cad1b139f"
		//appSecret := "a9c0700d1bbdc0e5770ab81e31deafb8"
		label := "part2"
	*/

	domain := "https://192.168.0.192"
	//a
	//appKey := "ad841c33e8fb243768ab014f064bb1e75e"
	//appSecret := "a7620337e87301b17513a63f6eb8d1fe"
	//sms
	appKey := "adabb4bea1296ecb0e71c909b628c8d563"
	appSecret := "bebc1a6b366433694829d3be36d0ff42"
	label := "part"
	keyStoreFileName := "sdk-keystore.jks"

	client, err := kadp.NewSMSClient(domain, appKey, appSecret, keyStoreFileName, "")
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
