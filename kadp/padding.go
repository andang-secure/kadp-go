package kadp

type Padding string

const (
	NoPadding    Padding = "NoPadding"
	PKCS5Padding Padding = "PKCS5Padding"
)
