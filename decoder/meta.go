package decoder

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/johnnyb/gocrypto/lrp"
)

// Meta is the chip metadata (called the PICCData in the docs).
// UID is an integer representation of the chips ID (convertible
// to a byte string by calling UidBytes().
// ReadCounter is the number of times the chip has been scanned.
type Meta struct {
	Uid         int64
	ReadCounter int32
	Keyset      *Keyset
}

// UidBytes decodes the UID into a byte string.
func (meta *Meta) UidBytes() []byte {
	uidBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(uidBytes, uint64(meta.Uid))
	return uidBytes[0:7]
}

// UidHex decodes the UID into a hex string.
func (meta *Meta) UidHex() string {
	return hex.EncodeToString(meta.UidBytes())
}

// ReadCounterBytes retrieves the ReadCounter as a byte array (the way it is stored on the chip)
func (meta *Meta) ReadCounterBytes() []byte {
	counterBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(counterBytes, uint32(meta.ReadCounter))
	return counterBytes[0:3]
}

func (meta *Meta) DecryptFileData(data []byte) []byte {
	if meta.Keyset.FileReadKey == KEY_NONE {
		return data
	}
	keyBytes := meta.Keyset.Keys[meta.Keyset.FileReadKey].GenerateKeyBytes(meta.UidBytes())
	switch meta.Keyset.Mode {
		case LRP:
			return DecryptLRP(keyBytes, 0, meta.ReadCounterBytes(), data)
		case AES:
			return DecryptAES(keyBytes, data)
		default:
			panic("Unknown encryption mode")
	}
}

func (meta *Meta) GenerateValidationCode(data []byte) []byte {
	if meta.Keyset.AuthenticationKey == KEY_NONE {
		return []byte{}
	}

	if data == nil {
		data = []byte{}
	}

	macKey := meta.Keyset.Keys[meta.Keyset.AuthenticationKey].GenerateKeyBytes(meta.UidBytes())

	switch meta.Keyset.Mode {
	case LRP:
		return meta.generateLRPMACValidationCode(macKey, data)
	case AES:
		return meta.generateAESMACValidationCode(macKey, data)
	default:
		panic("Bad Encryption Mode")
	}
}

func (meta *Meta) generateLRPMACValidationCode(macKey []byte, extraData []byte) []byte {
	sessKey := meta.GenerateLRPSessionMACKey(macKey)
	mc := lrp.NewStandardMultiCipher(sessKey)
	c := mc.CipherForMAC(0)

	result := c.CMAC(extraData)
	return []byte{result[1], result[3], result[5], result[7], result[9], result[11], result[13], result[15]}
}

func (meta *Meta) generateAESMACValidationCode(macKey []byte, extradata []byte) []byte {
	sessKey := meta.GenerateAESSessionMACKey(macKey)
	result := ShortAESMAC(sessKey, extradata)
	return result
}

// GenerateLRPSessionMACKey takes the MAC key and generates a session key
// for MAC-ing using the LRP algorithm.
func (meta *Meta) GenerateLRPSessionMACKey(macKey []byte) []byte {
	uidBytes := meta.UidBytes()
	counterBytes := meta.ReadCounterBytes()
	// pg. 42 and https://github.com/icedevml/ntag424-ev2-crypto/blob/master/test_lrp_sdm.py
	sv := make([]byte, 16)
	// SV = 00h || 01h || 00h || 80h [ || UID] [ || SDMReadCtr] [ || ZeroPadding] || 1Eh || E1h
	sv[0] = 0x00
	sv[1] = 0x01
	sv[2] = 0x00
	sv[3] = 0x80
	svIdx := 4
	if meta.Uid > 0 {
		sv[4] = uidBytes[0]
		sv[5] = uidBytes[1]
		sv[6] = uidBytes[2]
		sv[7] = uidBytes[3]
		sv[8] = uidBytes[4]
		sv[9] = uidBytes[5]
		sv[10] = uidBytes[6]
		svIdx = 11
	}
	if meta.ReadCounter > 0 {
		sv[svIdx] = counterBytes[0]
		sv[svIdx+1] = counterBytes[1]
		sv[svIdx+2] = counterBytes[1]
		svIdx += 3
	}
	for svIdx != 14 {
		sv[svIdx] = 0x00
		svIdx++
	}
	sv[14] = 0x1e
	sv[15] = 0xe1

	newKey := LRPMAC(macKey, 0, sv)
	return newKey
}

// LRPMAC performs the MAC function using LRP.
func LRPMAC(key []byte, keyNum int, msg []byte) []byte {
	mc := lrp.NewStandardMultiCipher(key)
	c := mc.CipherForMAC(keyNum)
	return c.CMAC(msg)
}

// GenerateAESSessionMACKey generates a session MAC key for AES encryption.
func (meta *Meta) GenerateAESSessionMACKey(originalKey []byte) []byte {
	uidBytes := meta.UidBytes()
	counterBytes := meta.ReadCounterBytes()

	sv := make([]byte, 16)
	sv[0] = 0x3c
	sv[1] = 0xc3
	sv[2] = 0x00
	sv[3] = 0x01
	sv[4] = 0x00
	sv[5] = 0x80

	svIdx := 6
	if meta.Uid > 0 {
		sv[6] = uidBytes[0]
		sv[7] = uidBytes[1]
		sv[8] = uidBytes[2]
		sv[9] = uidBytes[3]
		sv[10] = uidBytes[4]
		sv[11] = uidBytes[5]
		sv[12] = uidBytes[6]
		svIdx = 13
	}
	if meta.ReadCounter > 0 {
		sv[svIdx] = counterBytes[0]
		sv[svIdx+1] = counterBytes[1]
		sv[svIdx+2] = counterBytes[1]
		svIdx += 3
	}
	for svIdx != 16 {
		sv[svIdx] = 0x00
		svIdx++
	}

	newKey := AESMAC(originalKey, sv)

	return newKey
}

// DecryptMetaLRPString decrypts metadata from the given string, assuming the string is encoded in hexadecimal.
func DecryptMetaLRPString(key []byte, data string) Meta {
	val, _ := hex.DecodeString(data)
	return DecryptMetaLRP(key, val)
}

// DecryptMetaLRP decrypts the data for LRP.
func DecryptMetaLRP(key []byte, data []byte) Meta {
	// meta := Deserialize(DecryptLRP(key, data[16:24], data[0:16]))
	meta := Deserialize(DecryptLRP(key, 0, data[0:8], data[8:24]))
	return meta
}

// DecryptMetaAESString decrypts metadata from the given string, assuming the string is encoded in hexadecimal.
func DecryptMetaAESString(key []byte, data string) Meta {
	val, _ := hex.DecodeString(data)
	return DecryptMetaAES(key, val)
}

func DecryptMetaAES(key []byte, data []byte) Meta {
	meta := Deserialize(DecryptAES(key, data))
	return meta
}

func DecodeUnencryptedBytes(data []byte) Meta {
	// Make enough room for the tag
	newData := make([]byte, 11)
	// Copy data
	copy(newData[1:], data)
	// Add tag
	newData[0] = 0b11000000

	// Switch Endian-ness
	newData[10] = data[7]
	newData[9] = data[8]
	newData[8] = data[9]

	return Deserialize(newData)
}

func Deserialize(data []byte) Meta {
	meta := Meta{
		Uid:         -1,
		ReadCounter: -1,
	}
	tag := data[0]
	curidx := 1
	if (tag & 0b10000000) == 0 {
		// no UID mirroring
	} else {
		uidBytes := make([]byte, 8)
		copy(uidBytes, data[curidx:(curidx+7)])
		meta.Uid = int64(binary.LittleEndian.Uint64(uidBytes))
		curidx += 7
	}
	if (tag & 0b01000000) == 0 {
		// No tag couter
	} else {
		counterBytes := make([]byte, 4)
		copy(counterBytes, data[curidx:(curidx+3)])
		meta.ReadCounter = int32(binary.LittleEndian.Uint32(counterBytes))
	}

	return meta
}
