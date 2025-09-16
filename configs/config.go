package configs

//KmsConfig
/**
 * Represents the configuration for the Key Management System (KMS).
 * This class encapsulates the necessary settings and parameters for managing the KMS.
 * @author my
 */
type KmsConfig struct {
	Domain           string // 域名
	Credential       string // 用户KADP令牌
	RegisterToken    string // 注册令牌
	KeystoreFileName string
	KeystorePassword string
}
