package main


//this is simple function for encryption [ref: https://en.wikipedia.org/wiki/XOR_cipher]
//but its better to have more standard ways (AES,Triple DES,RSA,BlowFish)

func simple_xor(bytes []byte,key []byte) []byte{
	var rtn []byte
	var i int
	len_xor_key:=len(key)
	rtn = make([]byte,len(bytes))
	for i=0;i<len(bytes);i++{
		rtn[i]=key[i%len_xor_key] ^ bytes[i]
	}
	return rtn
}

// this method decript packet by specified encription
// if there is no encription method we return input bytes array
func DecryptPacket(bytes []byte,config *vpnConfig) ([]byte,error) {
	if(config.encryptionMethod =="xor"){
		return simple_xor(bytes,config.xorKey),nil
	}
	return bytes,nil
}

//EncryptPacket
func EncryptPacket(bytes []byte,config *vpnConfig) ([]byte,error){
	if(config.encryptionMethod =="xor"){
		return simple_xor(bytes,config.xorKey),nil
	}
	return  bytes,nil

}
