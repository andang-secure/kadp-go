package configs

const (
	MAIN_KEY     = "mainKey"
	ANALYSIS_KEY = "uF1jG4lH6vU6cZ9b"
	KEY          = "XIANANDANGGONGSI"
	Alg          = "rsa"
	RSA          = "rsa"
	SM2          = "sm2"
)

const (
	TOKEN  = "token"
	POST   = "POST"
	GET    = "GET"
	DELETE = "DELETE"
)

const (
	AUTH_URL    = "/v1/ksp/open_api/auth"
	REGISTE_URL = "/v1/ksp/open_api/kadp/register"
	KEK_URL     = "/v1/ksp/open_api/dek_text"
	DEK_URL     = "/v1/ksp/open_api/dek"
)

// 密钥管理部分
const (
	KEY_LIST_URL = "/v1/ksp/open_api/key/list"
)

// State 密钥状态枚举
type State int

const (
	StateActive State = iota
	StateInactive
	StateDestroyed
	StateCompromised
)
