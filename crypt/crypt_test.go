package crypt

import (
	"fmt"
	"testing"
)

func TestMD5(*testing.T) {
	fmt.Println(MD5V1([]byte("dh9h23jed239dh")))
	fmt.Println(MD5V2([]byte("dh9h23jed239dh")))
}

func TestBase64(*testing.T) {
	fmt.Println(Base64StdEncode([]byte("deefd2ff43f")))
}
