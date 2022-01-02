package main

import (
	"github.com/johnnyb/nfc-sun-decoder/decoder"
)

func readKey(keyset *decoder.Keyset, keyData []byte, application []byte) (keyIdx int) {
	if keyData == nil || len(keyData) == 0 {
		return decoder.KEY_NONE
	}
	key := decoder.Key{
		KeyData: keyData,	
	}
	if application != nil {
		key.Diversified = true
		key.Application = application
	}
	keyset.Keys = append(keyset.Keys, key)
	return len(keyset.Keys) - 1
}

func readKeyset() *decoder.Keyset {
	// Decode flags
	metaKey := mustDecodePtr(metaKeyData)
	fileKey := mustDecodePtr(fileKeyData)
	macKey := mustDecodePtr(macKeyData)
	macKeyApplication := mustDecodePtr(macKeyApplicationData)
	usesLrp := *usesLrpData

	keyset := &decoder.Keyset{
		Mode: decoder.AES,
		Keys: []decoder.Key{},
	}

	if usesLrp {
		keyset.Mode = decoder.LRP
	}

	keyset.MetaReadKey = readKey(keyset, metaKey, nil)
	keyset.FileReadKey = readKey(keyset, fileKey, nil)
	keyset.AuthenticationKey = readKey(keyset, macKey, macKeyApplication)

	return keyset
}

