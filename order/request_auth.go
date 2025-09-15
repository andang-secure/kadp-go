package order

type RegisterReq struct {
	MacAddr string `json:"mac_addr"`
	IP      string `json:"ip"`
	System  string `json:"system"`
	Token   string `json:"token"`
}

type AuthReq struct {
	MacAddr string `json:"mac_addr"`
	IP      string `json:"ip"`
	System  string `json:"system"`
	Pub     string `json:"pub"`
	Alg     string `json:"alg"`
}

type TempKeyData struct {
	RandomKey         string `json:"random_key"`
	TempDekCiphertext string `json:"temp_dek_ciphertext"`
	ExpirationDate    string `json:"expiration_date"`
	Mac               string `json:"mac"`
}

type KekReq struct {
	Label  string `json:"label"`
	Length int    `json:"length"`
}
