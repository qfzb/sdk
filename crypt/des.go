package crypt

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"

	"github.com/forgoer/openssl"
)

func pkcs5Padding(cipherText []byte, size int) []byte {
	padding := size - len(cipherText)%size
	padTest := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padTest...)
}

// des加密
func DesCBCEncrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))

	blockMode := cipher.NewCBCEncrypter(block, []byte(iv))
	blockMode.CryptBlocks(cryptText, data)
	return cryptText, nil
}

// Des3CBCEncrypt ...
func Des3CBCEncrypt(src, key []byte) ([]byte, error) {
	if len(key) < Des3KeyLen {
		return nil, fmt.Errorf("error key")
	}
	return openssl.Des3CBCEncrypt(src, key[:Des3KeyLen], []byte(iv), openssl.PKCS5_PADDING)
}

// Des3CBCDecrypt ...
func Des3CBCDecrypt(src, key []byte) ([]byte, error) {
	if len(key) < Des3KeyLen {
		return nil, fmt.Errorf("error key")
	}
	return openssl.Des3CBCDecrypt(src, key[:Des3KeyLen], []byte(iv), openssl.PKCS5_PADDING)
}
