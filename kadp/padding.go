package kadp

type Padding string

const (
	NoPadding       Padding = "NoPadding"
	PKCS5Padding    Padding = "PKCS5Padding"
	PKCS7Padding    Padding = "PKCS7Padding"
	ISO10126Padding Padding = "ISO10126Padding"
	ZeroPadding     Padding = "ZeroPadding"
)
