package sdk

import (
	"fmt"
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
	fmt.Println(plainText, uuid)
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

func (lsc *LiveSDKClient) QueryAnchorFrozenStatus(userId int) string {
	return ""
}

func (lsc *LiveSDKClient) ExtractRequestParams(requestBody string) map[string](interface{}) {
	ret := gjson.GetMany(requestBody, "payload", "timeStamp", "signature")
	if len(ret) != 3 {
		return nil
	}
	checkStr := ret[0].String() + ret[1].String() + lsc.SignKey
	md5 := crypt.MD5V1([]byte(checkStr))
	fmt.Printf("checkStr:%s MD5:%s", checkStr, md5)
	if ret[2].String() != md5 {
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
