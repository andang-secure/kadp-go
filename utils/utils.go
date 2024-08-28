package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
)

// Request is used wrap http request
type Request struct {
	Protocol string
	Port     int
	Method   string
	Pathname string
	Domain   string
	Headers  map[string]string
	Query    map[string]string
	Body     io.Reader
}

func SignString(stringToSign string, pri string) (result string, err error) {
	priByte, err := base64.StdEncoding.DecodeString(pri)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(priByte)
	pkcs1Privy, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256([]byte(stringToSign))
	sig, err := rsa.SignPKCS1v15(rand.Reader, pkcs1Privy, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func GetStringToSign(method string, headers map[string]string) (result string, err error) {
	contentSHA256 := headers["content-sha256"]

	contentType := headers["content-type"]

	date := headers["date"]

	header := method + "\n" + contentSHA256 + "\n" + contentType + "\n" + date + "\n"
	canonicalizedKSPHeaders := strings.Join([]string{
		fmt.Sprintf("x-ksp-acccesskeyid:%s", headers["x-ksp-acccesskeyid"]),
		fmt.Sprintf("x-ksp-apiname:%s", headers["x-ksp-apiname"]),
	}, "\n")
	canonicalizedResource := "/"

	return header + canonicalizedKSPHeaders + canonicalizedResource, err
}

func NewRequest() (req *Request) {
	return &Request{
		Headers: map[string]string{},
		Query:   map[string]string{},
	}
}
