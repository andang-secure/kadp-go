package kadp

type Fpe string

type Symmetry string

type Asymmetric string

type Digest string

type Hash string

const (
	FF1    Fpe        = "FF1"
	FF3    Fpe        = "FF1_3"
	AES    Symmetry   = "AES"
	SM4    Symmetry   = "SM4"
	DES    Symmetry   = "DES"
	SM2    Asymmetric = "SM2"
	RSA    Asymmetric = "RSA"
	SM3    Digest     = "SM3"
	Sha1   Hash       = "SHA-1"
	Sha256 Hash       = "SHA-256"
)

// FpeEncipherRequest FPE相关字段
type FpeEncipherRequest struct {
	Plaintext string
	CipherKey []byte
	Fpe       Fpe
	Tweak     string
	Alphabet  string
	Label     string
	Start     int
	End       int
}
type FpeDecipherRequest struct {
	Ciphertext string
	CipherKey  []byte
	Fpe        Fpe
	Tweak      string
	Alphabet   string
	Label      string
	Start      int
	End        int
}

// EncipherRequest 加密请求结构体
type EncipherRequest struct {
	Plaintext []byte
	CipherKey []byte
	Algorithm Symmetry
	Mode      Mode
	Padding   Padding
	Label     string
	IV        string
}

// DecryptRequest 解密请求结构体
type DecryptRequest struct {
	Ciphertext string
	CipherKey  []byte
	Algorithm  Symmetry
	Mode       Mode
	Padding    Padding
	Label      string
	IV         string
}

type AsymmetricEncryptRequest struct {
	Plaintext string
	Algorithm Asymmetric
	PublicKey string
}
type AsymmetricDecryptRequest struct {
	Ciphertext string
	Algorithm  Asymmetric
	PrivateKey string
}

type SM2SignRequest struct {
	Plaintext  string
	PrivateKey string
	Uid        []byte
}
type SM2VerifyRequest struct {
	Plaintext string
	PublicKey string
	R         string
	S         string
	Uid       []byte
}

type RsaSignRequest struct {
	Plaintext  string
	PrivateKey string
}
type RsaVerifyRequest struct {
	Plaintext string
	Signature string
	PublicKey string
}
type HmacRequest struct {
	CipherKey []byte
	Message   []byte
	Label     string
}
type HmacVerifyRequest struct {
	CipherKey []byte
	Message   []byte
	Label     string
	HmacVal   string
}
