package parse

import (
	"encoding/json"
	"os"
)

const jsonIndentSpacing = "    "
const jsonPrefix = ""

// GrypeFile takes the path to a json file containing a grype
// report, and parses it.
func GrypeFile(path string) (*GrypeDocument, error) {
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return GrypeReport(rawJSON)
}

// GrypeReport takes the content of a json file
// and returns a parsed string
func GrypeReport(rawJSON []byte) (*GrypeDocument, error) {
	grypeDocument := &GrypeDocument{}

	err := json.Unmarshal(rawJSON, grypeDocument)
	if err != nil {
		return nil, err
	}

	return grypeDocument, nil
}

// GetJSON formats the report as an indented JSON string.
func (grypeDocument *GrypeDocument) GetJSON() (string, error) {
	rawJSON, err := json.MarshalIndent(grypeDocument, jsonPrefix, jsonIndentSpacing)
	return string(rawJSON), err
}
