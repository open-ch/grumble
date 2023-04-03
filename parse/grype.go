package parse

import (
	"bytes"
	"encoding/json"
	"os"
)

const jsonIndentSpacing = "    "
const jsonPrefix = ""

func ParseGrype(path string) (string, error) {
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, rawJSON, jsonPrefix, jsonIndentSpacing)
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}
