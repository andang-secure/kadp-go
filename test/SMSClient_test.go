package test

import (
	"fmt"
	kadp "github.com/andang-secure/kadp-go/openapi-credential"
	"testing"
)

func TestNewSMSClient(t *testing.T) {
	url := "https://192.168.0.130:8390"
	domain := 1
	appKey := "ad69d9f4c549b061f38f9debbc718f9e2c"
	appSecret := "38bb2231cae51896d38635a5e32b7c50"
	keyStoreFileName := "sdk-keystore.jks"
	registerToken := "TxfzmhSA+q7yw6Fd9w63PA4FiJm+iii5/FyEzGyOrjSz3N7KOsfYvNLUQDuEOTLX"

	client, err := kadp.NewSMSClient(url, domain, appKey, appSecret, keyStoreFileName, registerToken)
	//client, err := kadp.NewSMSClient(domain, appKey, appSecret, keyStoreFileName, "", registerToken)
	if err != nil {
		t.Errorf("Failed to create SMSClient: %v", err)
	}

	if client == nil {
		t.Error("SMSClient is nil")
	}

	label := "QIANG"

	str, err := client.GetSmsCipherText(label)
	if err != nil {
		t.Errorf("getSmsCipherText failed: %v", err)
	}
	fmt.Println("str", str)

}
