package decoder

import (
	"crypto/aes"

	"github.com/aead/cmac"
)

func AESMAC(key []byte, data []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	h, err := cmac.NewWithTagSize(cipher, 16)
	if err != nil {
		panic(err)
	}

	_, err = h.Write(data)
	if err != nil {
		panic(err)
	}

	result := h.Sum(nil)

	return result
}

func ShortAESMAC(key []byte, data []byte) []byte {
	result := AESMAC(key, data)
	finalResult := []byte{result[1], result[3], result[5], result[7], result[9], result[11], result[13], result[15]}

	return finalResult
}
