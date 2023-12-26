package global

type AuthResponse struct {
	Code      int               `json:"code"`
	Data      map[string]string `json:"data"`
	Msg       string            `json:"msg"`
	RequestID string            `json:"request_id"`
}
