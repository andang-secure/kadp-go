package kadp

type keyListRes struct {
	Code      int     `json:"code"`
	Msg       string  `json:"msg"`
	RequestID string  `json:"request_id"`
	Data      KeyList `json:"data"`
}

// KeyList 密钥列表项
type KeyList struct {
	Page  int        `json:"page"`
	Total int        `json:"total"`
	Data  []*KeyData `json:"data"`
}

type KeyData struct {
	Kid                      string      `json:"kid"`
	Name                     string      `json:"name"`
	Label                    string      `json:"label"`
	Version                  string      `json:"version"`
	UID                      int         `json:"uid"`
	Uname                    string      `json:"uname"`
	DomainID                 int         `json:"domain_id"`
	Type                     int         `json:"type"`
	TypeName                 string      `json:"type_name"`
	Algorithm                int         `json:"algorithm"`
	AlgorithmName            string      `json:"algorithm_name"`
	Size                     int         `json:"size"`
	Content                  string      `json:"content"`
	Kmip                     int         `json:"kmip"`
	KeyUsage                 string      `json:"key_usage"`
	State                    int         `json:"state"`
	ActivationDate           int64       `json:"activation_date"`
	DeactivationDate         int64       `json:"deactivation_date"`
	ProtectStartDate         int64       `json:"protect_start_date"`
	ProtectStopDate          int64       `json:"protect_stop_date"`
	DestroyDate              int64       `json:"destroy_date"`
	ArchiveDate              int64       `json:"archive_date"`
	CompromiseDate           int64       `json:"compromise_date"`
	CompromiseOccurrenceDate int64       `json:"compromise_occurrence_date"`
	CreatedTime              int64       `json:"created_time"`
	UpdatedTime              int64       `json:"updated_time"`
	DeletedTime              int64       `json:"deleted_time"`
	Source                   int         `json:"source"`
	Class                    int         `json:"class"`
	Kek                      string      `json:"kek"`
	PolicyType               int         `json:"policy_type"`
	CteVersioned             int         `json:"cte_versioned"`
	EncryptionMode           int         `json:"encryption_mode"`
	UniqueToClient           int         `json:"unique_to_client"`
	PersistentOnClient       int         `json:"persistent_on_client"`
	LawRecover               int         `json:"law_recover"`
	Deletable                int         `json:"deletable"`
	Exportable               int         `json:"exportable"`
	GroupData                interface{} `json:"group_data"`
	Kcv                      string      `json:"kcv"`
}

type createKeyRes struct {
	Code      int    `json:"code"`
	Msg       string `json:"msg"`
	RequestID string `json:"request_id"`
	Data      struct {
		Kid string `json:"kid"`
	} `json:"data"`
}

type keyInfoRes struct {
	Code      int         `json:"code"`
	Msg       string      `json:"msg"`
	RequestID string      `json:"request_id"`
	Data      KeyInfoData `json:"data"`
}

type KeyInfoData struct {
	Kid                      string      `json:"kid"`
	Name                     string      `json:"name"`
	Label                    string      `json:"label"`
	Version                  string      `json:"version"`
	UID                      int         `json:"uid"`
	Uname                    string      `json:"uname"`
	DomainID                 int         `json:"domain_id"`
	Type                     int         `json:"type"`
	TypeName                 string      `json:"type_name"`
	Algorithm                int         `json:"algorithm"`
	AlgorithmName            string      `json:"algorithm_name"`
	Size                     int         `json:"size"`
	Content                  string      `json:"content"`
	Kmip                     int         `json:"kmip"`
	KeyUsage                 []int       `json:"key_usage"`
	State                    int         `json:"state"`
	ActivationDate           int64       `json:"activation_date"`
	DeactivationDate         int64       `json:"deactivation_date"`
	ProtectStartDate         int64       `json:"protect_start_date"`
	ProtectStopDate          int64       `json:"protect_stop_date"`
	DestroyDate              int64       `json:"destroy_date"`
	ArchiveDate              int64       `json:"archive_date"`
	CompromiseDate           int64       `json:"compromise_date"`
	CompromiseOccurrenceDate int64       `json:"compromise_occurrence_date"`
	CreatedTime              int64       `json:"created_time"`
	UpdatedTime              int64       `json:"updated_time"`
	DeletedTime              int64       `json:"deleted_time"`
	Source                   int         `json:"source"`
	Class                    int         `json:"class"`
	Kek                      string      `json:"kek"`
	PolicyType               int         `json:"policy_type"`
	CteVersioned             int         `json:"cte_versioned"`
	EncryptionMode           int         `json:"encryption_mode"`
	UniqueToClient           int         `json:"unique_to_client"`
	PersistentOnClient       int         `json:"persistent_on_client"`
	LawRecover               int         `json:"law_recover"`
	Deletable                int         `json:"deletable"`
	Exportable               int         `json:"exportable"`
	GroupData                interface{} `json:"group_data"`
	Kcv                      string      `json:"kcv"`
}

type commonRes struct {
	Code      int         `json:"code"`
	Msg       string      `json:"msg"`
	RequestID string      `json:"request_id"`
	Data      interface{} `json:"data"`
}
