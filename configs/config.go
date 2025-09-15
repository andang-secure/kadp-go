package configs

const (
	KeystoreFileName = "kadp1.jks"
	KeystorePassword = "uF1jG4lH6vU6cZ9b"
)

//KmsConfig
/**
 * Represents the configuration for the Key Management System (KMS).
 * This class encapsulates the necessary settings and parameters for managing the KMS.
 * @author my
 */
type KmsConfig struct {
	Domain        string
	Credential    string
	RegisterToken string
}
