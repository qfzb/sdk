package sdk

import (
	"fmt"
	"regexp"
	"time"

	"github.com/qfzb/sdk/crypt"
	xjs "github.com/qfzb/sdk/utils/convert"

	uuid "github.com/satori/go.uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type LiveSDKClient struct {
	AppID   string
	Domain  string
	PriKey  string
	PubKey  string
	SignKey string
}

func CreateLiveSDKClient(id, dm, prk, puk, sk string) *LiveSDKClient {
	return &LiveSDKClient{
		AppID:   id,
		Domain:  dm,
		PriKey:  prk,
		PubKey:  puk,
		SignKey: sk,
	}
}

func (lsc *LiveSDKClient) GetToken(tokenType, enterLivePermission int, userId, name, avatar string) (string, error) {
	uuid := uuid.NewV4().String()
	nameAvatarMd5 := crypt.MD5V1([]byte(name + avatar))[:10]
	plainText := fmt.Sprintf(
		"%s.%d.%s.%d.%d.%s.%s",
		userId,
		time.Now().UnixNano()/1e6,
		lsc.AppID,
		tokenType,
		enterLivePermission,
		nameAvatarMd5,
		lsc.SignKey)
	cipherText1, err := crypt.Des3CBCEncrypt([]byte(plainText), []byte(uuid))
	if err != nil {
		return "", err
	}
	cipherText2, err := crypt.RSAEncrypt([]byte(uuid), []byte(lsc.PubKey))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", crypt.Base64StdEncode(cipherText1), crypt.Base64StdEncode(cipherText2)), nil
}

func (lsc *LiveSDKClient) checkSign(b []gjson.Result) bool {
	reg := regexp.MustCompile(`(:\s*[0-9]\d*)([,}])`)
	spy := reg.ReplaceAllString(b[0].String(), "${1}.0${2}")
	checkStr := spy + fmt.Sprintf("%E", b[1].Float()) + lsc.SignKey

	md5Str := crypt.MD5V1([]byte(checkStr))
	fmt.Printf("checkStr:%s md5:%s\n", checkStr, md5Str)
	if md5Str != b[2].String() {
		return false
	} else {
		return true
	}
}

func (lsc *LiveSDKClient) ExtractRequestParams(requestBody string) map[string](interface{}) {
	ret := gjson.GetMany(requestBody, "payload", "timeStamp", "signature")
	if len(ret) != 3 {
		return nil
	}
	if !lsc.checkSign(ret) {
		return nil
	}
	return xjs.JsonToMap(ret[0].String())
}

func (lsc *LiveSDKClient) EncryptResponseBody(code int, message string, data interface{}) string {
	uuid := uuid.NewV4().String()

	resJson, _ := sjson.Set("", "code", code)
	resJson, _ = sjson.Set(resJson, "message", message)
	resJson, _ = sjson.Set(resJson, "data", data)

	cipherText1, err := crypt.Des3CBCEncrypt([]byte(resJson), []byte(uuid))
	if err != nil {
		return ""
	}
	cipherText2, err := crypt.RSAEncrypt([]byte(uuid), []byte(lsc.PubKey))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s.%s", crypt.Base64StdEncode(cipherText1), crypt.Base64StdEncode(cipherText2))
}
