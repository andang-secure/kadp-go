package test

import (
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/kadp"
	"testing"
)

func TestKeyManage(t *testing.T) {
	domain := "http://192.168.0.129:8190"
	credential := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEBz2tOQppjI+aYgZTgZ/CwzXXc3iEQVF7qe+a2usg9QBdY67ORoqwYxZliQDc+vacNnnoeIuF7eJZONFzvHJ643vyi5acprwRwUZmtaubc2WK/wXvw2Jk/G8OT2I+RsuuotTwSMgiWTbvhBw19fAyR59ucNtrzz1Le8Toe9tFg/JwEzzqgHikvIBo1JUBsKEjE8ttmVh5Xq2QcqPMdSB8uVo5NuJaqzase6ZbLLIZhdsw3xJq3vRzbhlrpArZxCGP0+HYOS4xtkHELjQ1ZAwckfcxxmyVDPhuXNhjOEfTbPF9HTh7smTEA27he9ccPYNzMjlyYEVGZVnktMxg9igdTHtXBLfDZRoMe12owLE9M7UZmjYMoPggrIv0j5jtwxtj2za+kvuCfRZh2ZcNnf8XyrivNLWJEm2EmFc9OHTGXGn/EHTQ0q/uNsGnCDSClLApA=="
	registerToken := "hnludUczLOwZfj0t84j1Eh0btPVNviLgPSjOfuS8oKaNNLACoKUd56YNb31jzU+d"

	KSPClient, err := kadp.NewKADPClient(&configs.KmsConfig{
		Domain:           domain,
		Credential:       credential,
		RegisterToken:    registerToken,
		KeystoreFileName: "keystore1.jks",
		KeystorePassword: "123456",
	})
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println("ok")

	createKeyRequest := &kadp.CreateKeyRequest{
		Name:      "DBG_" + "1d1d1d2w1",
		Algorithm: 4,
		Size:      128,
		KeyUsage:  "3,4",
	}

	keyId, err := KSPClient.KeyManager.CreateKey(createKeyRequest)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("CreateKey ok")
	fmt.Println("keyId", keyId)
}
