package util

import (
	"encoding/base64"
	"fmt"
)

func Base64Encode(bs []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(bs))
}

func Base64Decode(bs []byte) []byte {
	bs, err := base64.StdEncoding.DecodeString(string(bs))
	if err != nil {
		fmt.Printf("ERROR\t\tBase64Decode err=%v\n", err)
		return nil
	}
	return bs
}


