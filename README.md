# NFC SUN Decoder 
A Decoder for NXP 424 DNA SUN (Secure Unique) messages

This library makes decoding 424 DNA SUN messages easier.

While the 424 DNA chip supports having a wide variety of data on-chip, the SUN messages are often best-used for only generating the PICCData and ignoring the rest of the URL.
This allows the rest of the metadata to reside on the server.
Therefore, many convenience functions are written with this in mind.

To set up your DNA chip to only MAC the PICC data, set SDMMACInputOffset equal to SDMMacOffset.
This will cause it to MAC a zero-length string.  
Since the generated MAC session key includes the UID and the read counter, this validates these data fields.

## Basic Concepts

This library contains a few basic concepts:

* Keyset - this is a set of keys that are used for reading messages.  These can include diversified keys.  However, a diversified key can't be used to decrypt the Meta.
* Key - a key is either a direct key or a diversified key.
* Meta - this is the PICCData on the chip, as well as a pointer to the keyset being used.

The general process is this:

1. It's assumed that you already have the proper Keyset available.
2. You either:
  a. read the Meta from an encoded data (set with PICCDataOffset) using Keyset#DecodeEncryptedMetaString, or
  b. manually construct the Meta from parameters that give the UID and ReadCounter (don't forget to set the keyset itself!).
3. You then can decrypt file data (using Meta#DecryptFileData) or authenticate a string using a MAC (using Meta#GenerateValidationCode)

All of these can be combined for PICCData-only messages using Keyset#DecodeEncryptedMetaStringWithAuthenticator.
This returns the PICCData as a Meta, as well as a boolean telling you whether or not it successfully authenticated.

## Example Program

```
package main

import (
	"encoding/hex"
	"github.com/johnnyb/nfc-sun-decoder/decoder"
)

func main() {
	// Setup keys k0 and k1

	keyset := Keyset{
		Mode: AES,
		Keys: []Key{k0, k1},
		FileReadKey: 0,       // use k0
		MetaReadKey: 0,       // use k0
		AuthenticationKey: 1, // use k1
	}

	// metaString is the meta string to decrypt
	// authCode is the MAC code
	meta, validated := keyset.DecodeEncryptedMetaStringWithAuthenticator(metaString, authCode)

	// Print results
	fmt.Printf("Chip UID: %s, Read Counter: %d, Validated: %t\n", meta.UidHex(), meta.ReadCounter, validated)	
}

```
