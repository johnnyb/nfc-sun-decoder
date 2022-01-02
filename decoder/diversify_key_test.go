package decoder

import (
	"testing"
	"bytes"
	"encoding/hex"
)

func TestDiversifyKey(t *testing.T) {
	masterKey, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	application, _ := hex.DecodeString("3042F54E585020416275")
	chipUid, _ := hex.DecodeString("04782E21801D80")

	key := DiversifyKey(masterKey, application, chipUid)
	expectedKey, _ := hex.DecodeString("A8DD63A3B89D54B37CA802473FDA9175")
	if !bytes.Equal(key, expectedKey) {
		t.Errorf("Bad key diversification: Expected %s, received %s", hex.EncodeToString(expectedKey), hex.EncodeToString(key))
	}
}
