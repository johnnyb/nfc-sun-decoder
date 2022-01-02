package decoder

// Key is the type used to hold basic key information
// and generate diversified keys.
type Key struct {
	// KeyData is the bytes of the key (master key if using diversified keys).
	KeyData     []byte
	// Diversified tells whether this is a straight key or a diversified key.
	Diversified bool
	// Application tells the "application data" to use during diversification on diversified keys.
	Application []byte
}

// Generates a key.  Diversifies the key if it is set to be a diversified key.
// If it is not a diversified key, uidBytes can be nil.
func(key *Key) GenerateKeyBytes(uidBytes []byte) []byte {
	if !key.Diversified {
		return key.KeyData
	} else {
		return DiversifyKey(key.KeyData, key.Application, uidBytes)
	}
}
