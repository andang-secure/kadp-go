package kadp

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
)

func sha1Sum(message []byte) string {

	// SHA-1
	sha1Hash := sha1.Sum(message)
	shaHashBase64 := base64.StdEncoding.EncodeToString(sha1Hash[:])

	return shaHashBase64
}

func sha256Sum(message []byte) string {

	// SHA-256
	sha256Hash := sha256.Sum256(message)
	sha256HashBase64 := base64.StdEncoding.EncodeToString(sha256Hash[:])

	return sha256HashBase64
}
