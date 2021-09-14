package json

import "encoding/json"

// JsonToMap ...
func JsonToMap(str string) map[string]interface{} {
	var tempMap map[string]interface{}
	json.Unmarshal([]byte(str), &tempMap)
	return tempMap
}
