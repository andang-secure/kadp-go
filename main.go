package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {

	url := "https://192.168.0.135:8390"
	domain := 1
	appKey := "ad68408bb2dd8f235df8250beeaed7de62"
	appSecret := "a8c0cfa369742a1012cf184934956912"
	registerToken := "Aa/5qMa9MCcFAE1x7RR83kR1oIJKmDSFAEsZyBl75vaDtjFvqtrUD8eAAVrFK9Xf"
	label := "asdaa"

	//domain := "https://192.168.0.192"
	////cj
	//appKey := "ad6612922dbdc2169b31be8c22f28350fa"
	//appSecret := "b0e6d63f978418e0da4214912ddd4a9f"
	//label := "df"
	keyStoreFileName := "sdk-keystore.jks"

	client, err := kadp.NewSMSClient(url, domain, appKey, appSecret, keyStoreFileName, registerToken)
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
