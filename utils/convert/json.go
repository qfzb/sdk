package json

import "encoding/json"

// json转map函数
func JsonToMap(str string) map[string]interface{} {
	var tempMap map[string]interface{}
	json.Unmarshal([]byte(str), &tempMap)
	return tempMap
}
