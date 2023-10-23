package algorithm

type Fpe string

type Symmetry string

type Asymmetric string

const (
	FF1 Fpe        = "FF1"
	FF3 Fpe        = "FF1_3"
	AES Symmetry   = "AES"
	SM4 Symmetry   = "SM4"
	SM2 Asymmetric = "SM2"
	RSA Asymmetric = "RSA"
)
