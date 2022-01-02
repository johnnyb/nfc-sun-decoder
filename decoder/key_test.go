package decoder

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKey(t *testing.T) {
	a1bytes, _ := hex.DecodeString("07f23a4c407485ea3122ff242f763e77")
	app, _ := hex.DecodeString("3042f562696b65646e61")
	a1 := Key{
		KeyData: a1bytes,
		Diversified: true,
		Application: app,
	}

	uidb, _ := hex.DecodeString("0421272AAA6180")
	expectedKey, _ := hex.DecodeString("3C4459929939FED6A23C561A92999AD1")
	keyBytes := a1.GenerateKeyBytes(uidb)
	if !bytes.Equal(keyBytes, expectedKey) {
		t.Errorf("Error with key generation: Expected %s, received %s", hex.EncodeToString(expectedKey), hex.EncodeToString(keyBytes))
	}
}
