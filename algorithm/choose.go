package algorithm

type Fpe string

type Symmetry string

type Asymmetric string

type Digest string

const (
	FF1 Fpe        = "FF1"
	FF3 Fpe        = "FF1_3"
	AES Symmetry   = "AES"
	SM4 Symmetry   = "SM4"
	DES Symmetry   = "DES"
	SM2 Asymmetric = "SM2"
	RSA Asymmetric = "RSA"
	SM3 Digest     = "SM3"
)
