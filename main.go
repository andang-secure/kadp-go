package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {

	//url := "https://ksp.andang.cn"
	//domain := 1
	////coca
	//appKey := "ad68408bb2dd8f235df8250beeaed7de62"
	//appSecret := "b5ce2c51909959d928ca5b0de13f63e1"
	////cxzd
	////appKey := "adf3e4e1780036e9d681179ff60df05adf"
	////appSecret := "ac255974a32e24206493815e1f363805"
	//registerToken := "Aa/5qMa9MCcFAE1x7RR83kR1oIJKmDSFAEsZyBl75vaDtjFvqtrUD8eAAVrFK9Xf"
	//label := "test-01"

	url := "https://192.168.0.130:8390"
	domain := 1
	appKey := "ad69d9f4c549b061f38f9debbc718f9e2c"
	appSecret := "38bb2231cae51896d38635a5e32b7c50"
	registerToken := "Aa/5qMa9MCcFAE1x7RR83kR1oIJKmDSFAEsZyBl75vaDtjFvqtrUD8eAAVrFK9Xf"
	label := "QIANG"

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
