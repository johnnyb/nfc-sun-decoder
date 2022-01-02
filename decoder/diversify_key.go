package decoder

func DiversifyKey(masterKey []byte, application []byte, identifier []byte) []byte {
	diversificationData := []byte{0x01} // I don't think the 0x01 actually does anything, but the standard says it should be there
	diversificationData = append(diversificationData, identifier...)
	diversificationData = append(diversificationData, application...)
	newKey := AESMAC(masterKey, diversificationData)
	return newKey
}
