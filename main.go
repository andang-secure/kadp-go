package main

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
)

func main() {
	domain := "https://192.168.0.135:8390"
	appKey := "ad0101b2cf6612f4e52ba598c4f939f37f"
	appSecret := "a0e447962336afda68f10a55f97e12b8"
	label := "d"

	//domain := "https://192.168.0.192"
	//appKey := "coca"
	//appSecret := "165338fdb9a878f9a85203661c69eb74"
	//label := "zheng4"

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
