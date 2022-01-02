package decoder

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var testKey1 = []byte{0x70, 0xAE, 0x26, 0x64, 0xBC, 0xE1, 0x19, 0x96, 0x0D, 0x15, 0xEB, 0xE3, 0x81, 0x00, 0x79, 0xC5}
var testKey2Str = "04a4332aaa61800004a4332aaa618000"

func TestShortMac(t *testing.T) {
	ex1 := []byte{0x64, 0x00, 0x00, 0xFB, 0xAD, 0x62, 0x51, 0x00}
	ex1res := []byte{0x23, 0xAD, 0xB1, 0x9D, 0xDE, 0xD8, 0xDB, 0x91}


	result := ShortAESMAC(testKey1, ex1)
	if len(result) != 8 {
		t.Errorf("Wrong MAC length")
	}
	if !bytes.Equal(result, ex1res) {
		t.Errorf("Bad MAC.  Expected %s // Received %s", hex.EncodeToString(ex1res), hex.EncodeToString(result))
	}
}
