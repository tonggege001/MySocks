package core

import (
	"fmt"
	"math/rand"
)

const PasswordLength = 256

type Password [PasswordLength]byte

type Cipher struct {
	encodePassword *Password
	decodePassword *Password
}

// 加密原数据
func (cipher *Cipher) encode(bs []byte) {
	for i, v := range bs {
		bs[i] = cipher.encodePassword[v]
	}
}

// 解码原数据
func (cipher *Cipher) decode(bs []byte) {
	for i, v := range bs {
		bs[i] = cipher.decodePassword[v]
	}
}

// 新建一个编解码器
func NewCipher(password int64) *Cipher {
	rand.Seed(password)
	intArr := rand.Perm(PasswordLength)

	cipher := &Cipher{
		encodePassword: new(Password),
		decodePassword: new(Password),
	}

	for i, v := range intArr {
		cipher.encodePassword[i] = byte(v)
		cipher.decodePassword[v] = byte(i)
	}

	fmt.Printf("Cifer Encode: %v, \nDecode: %v\n", cipher.encodePassword, cipher.decodePassword)
	return cipher
}
