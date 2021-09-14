package sdk

import (
	"fmt"
	"testing"
)

func TestGetToken(*testing.T) {
	appId := "1"
	domain := "dsdfds.xyz"
	priKey := ""
	pubKey := "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMh8pcNaFgp1d36aNJypSXPLJ/Yz9DX3c3M3rSli6YhCe/k35qMFhiJlL2nBQl2cMmSyQYHPM0QtzeG7XsZJ3HrqVq7hoKvMmK+RX3M3VCVV6I3FPUQi8UZBqN1fUj2iAiZEqhI/foF22zHeO6W0pyuWlYDkFi+ye3izmDBVkkiwIDAQAB\n-----END PUBLIC KEY-----"
	signKey := "7oAizspc"

	name := "nasa"
	tokenType := 1
	enterLivePermission := 0
	userId := "123"
	avatar := "http://www.baidu.com"

	lsc := CreateLiveSDKClient(appId, domain, priKey, pubKey, signKey)
	token, err := lsc.GetToken(tokenType, enterLivePermission, userId, name, avatar)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(token)
	}

	fmt.Println(lsc.ExtractRequestParams(`
	{"payload":{"appId":"1"},"signature":"f7c9a7292029b19bb6f63bba59fb4345","timeStamp":1631260200114}`))
	fmt.Println(lsc.EncryptResponseBody(10000, "succ", `{"appId":"1"}`))
}
