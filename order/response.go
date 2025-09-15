package order

type KmsRes struct {
	Code      int    `json:"code"`
	Msg       string `json:"msg"`
	RequestID string `json:"request_id"`
	Data      string `json:"data"`
}

type KmsAuthRes struct {
	Code      int       `json:"code"`
	Msg       string    `json:"msg"`
	RequestID string    `json:"request_id"`
	Data      AuthToken `json:"data"`
}

type AuthToken struct {
	Token string `json:"token"`
}
