package decoder

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/johnnyb/gocrypto/lrp"
)

func TestMeta(t *testing.T) {
	var expectedUid int64 = 36136180498510340
	zeroKeyBinary, _ := hex.DecodeString(zeroKey)

	// NOTE - these both decrypt to the same thing, but differ due to random padding
	msg, _ := hex.DecodeString("AB9A48A5286493D4476603F9F441F918")
	meta := DecryptMetaAES(zeroKeyBinary, msg)
	if meta.Uid != expectedUid {
		t.Errorf("Wrong UID.  Expected %d, Received %d", expectedUid, meta.Uid)
	}
	if meta.ReadCounter >= 0 {
		t.Errorf("Read counter should not be set: %d", meta.ReadCounter)
	}

	msgString := "AEB5461B56F2A992A8945C5F240FC261"
	meta = DecryptMetaAESString(zeroKeyBinary, msgString)
	if meta.Uid != expectedUid {
		t.Errorf("Wrong UID.  Expected %d, Received %d", expectedUid, meta.Uid)
	}
	if meta.ReadCounter >= 0 {
		t.Errorf("Read counter should not be set")
	}

	msg, _ = hex.DecodeString("B56A7F9330713674C91A3F305332763B")
	meta = DecryptMetaAES(zeroKeyBinary, msg)
	if meta.Uid != expectedUid {
		t.Errorf("Wrong UID.  Expected %d, Received %d", expectedUid, meta.Uid)
	}
	if meta.ReadCounter != 36 {
		t.Errorf("Bad read counter: Expected %d, Received %d", 36, meta.ReadCounter)
	}

	msg, _ = hex.DecodeString("8AB1E6B164F052B424A2E364934E4924")
	meta = DecryptMetaAES(zeroKeyBinary, msg)
	if meta.Uid != expectedUid {
		t.Errorf("Wrong UID.  Expected %d, Received %d", expectedUid, meta.Uid)
	}
	if meta.ReadCounter != 43 {
		t.Errorf("Bad read counter: Expected %d, Received %d", 43, meta.ReadCounter)
	}

	msg, _ = hex.DecodeString("B0949E0D74C8CB271785422C24A58EF5")
	meta = DecryptMetaAES(zeroKeyBinary, msg)
	if meta.Uid != expectedUid {
		t.Errorf("Wrong UID.  Expected %d, Received %d", expectedUid, meta.Uid)
	}
	if meta.ReadCounter != 45 {
		t.Errorf("Bad read counter: Expected %d, Received %d", 45, meta.ReadCounter)
	}
}

func TestGenerateSessionMACKey(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	metaBytes, _ := hex.DecodeString("C704DE5F1EACC0403D0000")
	meta := Deserialize(metaBytes)
	newKey := meta.GenerateAESSessionMACKey(key)
	correctKey, _ := hex.DecodeString("3FB5F6E3A807A03D5E3570ACE393776F")
	if !bytes.Equal(newKey, correctKey) {
		t.Errorf("Error generatign key: Expected %s, Received %s", hex.EncodeToString(correctKey), hex.EncodeToString(newKey))
	}
}

func TestMACValidationCode(t *testing.T) {
	macKey, _ := hex.DecodeString("04a4332aaa61800004a4332aaa618000")
	keyset := Keyset{
		Mode: AES,
		Keys: []Key{
			Key{
				KeyData:macKey,
			},
		},
		AuthenticationKey: 0,
	}
	meta := Meta{
		ReadCounter: 33,
		Uid:         36136180499325956,
		Keyset: &keyset,
	}
	macBytes := meta.GenerateValidationCode([]byte{})
	expectation, _ := hex.DecodeString("4DF5A6877EA54754")
	if !bytes.Equal(expectation, macBytes) {
		t.Errorf("Did not generate MAC validation code correctly: Expected %s, received %s", hex.EncodeToString(expectation), hex.EncodeToString(macBytes))
	}
}

func TestWebMac(t *testing.T) {
	url := "https://webhooks.s-digital.co/dev/dna/3983AEF66052A9C9FBE82821F8E23ECA/4DF5A6877EA54754"
	parts := strings.Split(url, "/")
	encrypted := parts[len(parts)-2]
	mac := parts[len(parts)-1]
	macBytes, _ := hex.DecodeString(mac)
	piccKey, _ := hex.DecodeString("00000000000000000000000000000011")
	meta := DecryptMetaAESString(piccKey, encrypted)
	macKey, _ := hex.DecodeString("04a4332aaa61800004a4332aaa618000")
	macSessionKey := meta.GenerateAESSessionMACKey(macKey)

	result := ShortAESMAC(macSessionKey, []byte{})

	if !bytes.Equal(result, macBytes) {
		t.Errorf("Error calculating session MAC: Expected %s, received %s", hex.EncodeToString(result), mac)
	}
}

func TestFromPython(t *testing.T) {
	// From https://github.com/icedevml/ntag424-ev2-crypto/blob/master/test_lrp_sdm.py
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	msg, _ := hex.DecodeString("AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293")
	expectation, _ := hex.DecodeString("c7042e1d222a63806a000016e2ca89d1")

	// mac := "5E3DB82C19E3865F"

	mc := lrp.NewStandardMultiCipher(key)
	c := mc.Cipher(0)
	c.Counter = binary.BigEndian.Uint64(msg[0:8])
	result := c.DecryptAll(msg[8:24], false)
	if !bytes.Equal(result, expectation) {
		t.Errorf("Bad result from decryption: %s", hex.EncodeToString(result))
	}
}

func TestMetaLRP(t *testing.T) {
	key, _ := hex.DecodeString("e6cbb56d350c25eda052b27f81b1c884")
	macMasterKey, _ := hex.DecodeString("07f23a4c407485ea3122ff242f763e77")
	appdata, _ := hex.DecodeString("3042f562696b65646e61")
	data := "9A07B1067A4B33687962AC328A34DD396510F12C4B066FE3"
	meta := DecryptMetaLRPString(key, data)
	meta.Keyset = &Keyset{
		Mode: LRP,
		Keys: []Key{
			Key{
				KeyData: key,
			},
			Key{
				KeyData: macMasterKey,
				Diversified: true,
				Application: appdata,
			},
		},
		MetaReadKey: 0,
		AuthenticationKey: 1,
	}
	if meta.Uid != 36136180498514436 {
		t.Errorf("Meta Uid: %d, Counter %d", meta.Uid, meta.ReadCounter)
	}
	mac, _ := hex.DecodeString("AA5D0ADA7ED558DC")
	code := meta.GenerateValidationCode(nil)
	if !bytes.Equal(mac, code) {
		t.Errorf("Bad LRP MAC: %s", hex.EncodeToString(code))
	}
}
