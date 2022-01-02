package decoder

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/johnnyb/gocrypto/lrp"
)

func DecryptAES(key []byte, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCDecrypter(c, make([]byte, 16))
	dst := make([]byte, len(data))
	cbc.CryptBlocks(dst, data)

	return dst
}

func DecryptLRP(key []byte, keynum int, counterBytes []byte, data []byte) []byte {
	mc := lrp.NewStandardMultiCipher(key)

	counter := binary.BigEndian.Uint64(counterBytes)
	c := mc.Cipher(keynum)
	c.Counter = uint64(counter)
	// Not sure if I should force CounterSize to 16 or just leave it to `normal'
	c.CounterSize = 16

	return c.DecryptAll(data, false)
}
