package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {
	domain := "https://192.168.0.135:8190"
	appKey := "zl"
	appSecret := "123456"
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

	label := "1708"

	str, err := client.GetSmsCipherText(label)
	if err != nil {
		fmt.Printf("getSmsCipherText failed: %v", err)
		return
	}
	fmt.Println("str", str)
}
