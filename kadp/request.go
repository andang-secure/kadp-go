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

//KeyManager

// KeyListParam 密钥列表查询参数
type KeyListParam struct {
	Page     string `json:"page"`
	PageSize string `json:"page_size"`
}

type CreateKeyRequest struct {
	Name      string `json:"name"`
	Algorithm int    `json:"algorithm"`
	Size      int    `json:"size"`
	KeyUsage  string `json:"key_usage"`
	Label     string `json:"label"`
}

type deleteKeyRequest struct {
	Id int64 `json:"id"`
}

type UpdateKeyRequest struct {
	Id         int64  `json:"id"`
	Deletable  int    `json:"deletable"`
	Exportable int    `json:"exportable"`
	KeyUsage   string `json:"key_usage"`
}

type commonKidRequest struct {
	Id int64 `json:"id"`
}

type CloneKeyRequest struct {
	Id   int64  `json:"id"`
	Name string `json:"name"`
}

type DistributeKeyRequest struct {
	PublicKey string `json:"public_key"`
	Algorithm int    `json:"algorithm"`
	KeyName   string `json:"key_name"`
	Id        int64  `json:"id"`
}

type ExportKeyRequest struct {
	KeyId      string `json:"key_id"`
	KeyName    string `json:"key_name"`
	KeyVersion int64  `json:"key_version"`
}
