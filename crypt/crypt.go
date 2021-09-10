package crypt

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	iv         = "01234567"
	Des3KeyLen = 24
)

// MD5V1 ...
func MD5V1(src []byte) string {
	h := md5.New()
	h.Write(src)
	return hex.EncodeToString(h.Sum(nil))
}

// MD5V2 ...
func MD5V2(src []byte) string {
	return fmt.Sprintf("%x", md5.Sum(src))
}

// Base64StdEncode ...
func Base64StdEncode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

// Base64StdDecode ...
func Base64StdDecode(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}
