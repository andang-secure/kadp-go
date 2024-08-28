package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {
	//domain := "https://192.168.0.135:8390"
	//appKey := "zl"
	//appSecret := "2fb1a3cd7223c60b413f0135c4450f3b"
	//label := "eee"

	domain := "https://192.168.0.192:7443"
	//appKey := "coca"
	//appSecret := "054035cd60e81722207450489f7ed07d"
	//label := "co"

	//domain := "https://192.168.0.192"
	appKey := "coca"
	appSecret := "165338fdb9a878f9a85203661c69eb74"
	label := "zheng4"

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
