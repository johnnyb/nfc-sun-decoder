package decoder

import (
	"encoding/hex"
	"testing"
)

var zeroKey = "00000000000000000000000000000000"
var oneKey = "00000000000000000000000000000001"

func TestDecryptAES(t *testing.T) {
	testcases := [][]string{
		{zeroKey, "AB9A48A5286493D4476603F9F441F918", "870432272aaa6180eedca6567298ba89"},
		{zeroKey, "AEB5461B56F2A992A8945C5F240FC261", "870432272aaa618037b0b68181d9ee69"},
	}
	for _, testcase := range testcases {
		key, _ := hex.DecodeString(testcase[0])
		data, _ := hex.DecodeString(testcase[1])
		results := DecryptAES(key, data)
		resultsHex := hex.EncodeToString(results)
		if resultsHex != testcase[2] {
			t.Errorf("Did not decrypt correctly: Expected: %s // Received %s // Key %s", testcase[2], resultsHex, testcase[0])
		}
	}
}

/*
func TestDecryptLRP(t *testing.T) {
	// key, _ := hex.DecodeString("e6cbb56d350c25eda052b27f81b1c884")
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	data, _ := hex.DecodeString("9A07B1067A4B33687962AC328A34DD396510F12C4B066FE3")
	results := DecryptLRP(key, data[0:8], data[8:])
	resultsHex := hex.EncodeToString(results)
	t.Errorf("Result: %s", resultsHex)
}
*/
