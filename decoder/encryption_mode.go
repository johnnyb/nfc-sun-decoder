package decoder

type EncryptionMode int

const (
	UNKNOWN EncryptionMode = iota
	AES     EncryptionMode = iota
	LRP     EncryptionMode = iota
)
