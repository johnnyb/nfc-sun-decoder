package main

import (
	"encoding/hex"
)

func mustDecodePtr(str *string) []byte {
	if str == nil {
		return nil
	}
	return mustDecode(*str)
}

func mustDecode(str string) []byte {
	if str == "" {
		return nil
	}
	result, err := hex.DecodeString(str)
	if err != nil {
		panic("Invalid hex string: " + str)
	}

	return result
}


