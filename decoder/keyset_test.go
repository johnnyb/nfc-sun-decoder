package decoder

import (
	"encoding/hex"
	"testing"
)

func TestKeyset(t *testing.T) {
	e1bytes, _ := hex.DecodeString("e6cbb56d350c25eda052b27f81b1c884")
	e1 := Key{
		KeyData: e1bytes,
		Diversified: false,
	}
	a1bytes, _ := hex.DecodeString("07f23a4c407485ea3122ff242f763e77")
	app, _ := hex.DecodeString("3042f562696b65646e61")
	a1 := Key{
		KeyData: a1bytes,
		Diversified: true,
		Application: app,
	}
	keyset := Keyset{
		Mode: AES,
		Keys: []Key{e1, a1},
		FileReadKey: 0,
		MetaReadKey: 0,
		AuthenticationKey: 1,
	}

	// Try unencrypted payloads
	oldMeta := keyset.MetaReadKey
	// Should auto-detect meta encryption being off
	// keyset.MetaReadKey = KEY_NONE
	meta, validated := keyset.DecodeEncryptedMetaStringWithAuthenticator("0471862A506380000003", "637618472FE7D110")
	if !validated {
		t.Errorf("Not validated, but should have been")
	}
	if meta.ReadCounter != 3 {
		t.Errorf("Wrong read counter: %d", meta.ReadCounter)
	}
	if meta.Uid != 36137992980951300 {
		t.Errorf("Wrong UID: %d", meta.Uid)
	}
	meta, validated = keyset.DecodeEncryptedMetaStringWithAuthenticator("0471862A506380000003", "637618472FE7D111")
	if validated {
		t.Errorf("Validated, but should not have been")
	}

	// Now do encrypted payloads
	keyset.MetaReadKey = oldMeta
	meta, validated = keyset.DecodeEncryptedMetaStringWithAuthenticator("CBF5374BC4874E7AE53961E6533DDC5F", "C4B7E3310EFC2FA3")
	if !validated {
		t.Errorf("Not validated, but should have been")
	}
	if meta.Uid != 36136180498505988 {
		t.Errorf("Wrong UID: %d", meta.Uid)
	}
	if meta.ReadCounter != 2 {
		t.Errorf("Wrong read counter: %d", meta.ReadCounter)
	}
}
