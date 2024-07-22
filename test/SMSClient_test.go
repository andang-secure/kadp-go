package test

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
	"testing"
)

func TestNewSMSClient(t *testing.T) {
	domain := "https://192.168.0.135:8190"
	appKey := "admin"
	appSecret := "123456"
	keyStoreFileName := "sdk-keystore.jks"

	client, err := kadp.NewSMSClient(domain, appKey, appSecret, keyStoreFileName, "")
	if err != nil {
		t.Errorf("Failed to create SMSClient: %v", err)
	}

	if client == nil {
		t.Error("SMSClient is nil")
	}

	label := "1708"

	str, err := client.GetSmsCipherText(label)
	if err != nil {
		t.Errorf("getSmsCipherText failed: %v", err)
	}
	fmt.Println("str", str)

}
