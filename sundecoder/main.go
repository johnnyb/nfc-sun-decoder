package main

import (
	"flag"
	"fmt"
)

func main() {
	flag.Parse()
	keyset := readKeyset()

	if *piccData == "" {
		panic("No data specified to decode!")
	}

	meta, validated := keyset.DecodeEncryptedMetaStringWithAuthenticator(*piccData, *macCode)
	fmt.Printf("ChipUID: %s\nReadCounter: %d\nValidated: %t\n", meta.UidHex(), meta.ReadCounter, validated)	
}
