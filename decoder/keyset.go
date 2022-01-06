package decoder

import (
	"bytes"
	"encoding/hex"
)

const KEY_NONE = -1

// Keyset maintains information about a set of keys on a chip.
// DNA chips can support 5 keys.  This does not require that the key
// structure be mimicked, but allows for it.
type Keyset struct {
	Mode EncryptionMode
	Keys []Key
	MetaReadKey int 
	FileReadKey int
	AuthenticationKey int
}

// DecodeEncryptedMetaStringWithAuthenticator is a convenience function for decoding meta-only messages with meta-only MACs.
func (keyset *Keyset) DecodeEncryptedMetaStringWithAuthenticator(dataStr string, authenticatorStr string) (meta Meta, validated bool) {
	// Auto-turn-off encryption if it is too short
	if len(dataStr) == 20 && keyset.MetaReadKey != KEY_NONE {
		tmpKeyset := *keyset
		tmpKeyset.MetaReadKey = KEY_NONE
		keyset = &tmpKeyset
	}

	meta = keyset.DecodeEncryptedMetaString(dataStr)
	code := meta.GenerateValidationCode([]byte{})

	authenticator, err := hex.DecodeString(authenticatorStr)
	if err != nil {
		validated = false
	} else {
		validated = bytes.Equal(code, authenticator)
	}

	return
}

// DecodeEncryptedMetaString decodes encrypted metadata
func (keyset *Keyset) DecodeEncryptedMetaString(dataStr string) (meta Meta) {
	data, err := hex.DecodeString(dataStr)
	if err != nil {
		return Meta{
			Keyset: keyset,
		}
	}

	return keyset.DecodeEncryptedMeta(data)
}

func (keyset *Keyset) DecodeEncryptedMeta(data []byte) (meta Meta) {
	if keyset.MetaReadKey == KEY_NONE {
		meta = DecodeUnencryptedBytes(data)
	} else {
		keyBytes := keyset.Keys[keyset.MetaReadKey].GenerateKeyBytes(nil)
		switch keyset.Mode {
		case AES:
			meta = DecryptMetaAES(keyBytes, data)

		case LRP:
			meta = DecryptMetaLRP(keyBytes, data)

		default:
			panic("Unknown Encryption Mode")
		}
	}

	meta.Keyset = keyset

	return
}

