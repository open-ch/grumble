package parse

import (
	"bytes"
	"encoding/json"
	"os"
)

const jsonIndentSpacing = "    "
const jsonPrefix = ""

// GrypeFile takes the path to a json file containing a grype
// report, and parses it.
func GrypeFile(path string) (string, error) {
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return GrypeReport(rawJSON)
}

// GrypeReport takes the content of a json file
// and returns a parsed string
func GrypeReport(rawJSON []byte) (string, error) {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, rawJSON, jsonPrefix, jsonIndentSpacing)
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}
