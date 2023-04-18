package parse

import (
	"encoding/json"
	"os"

	"github.com/open-ch/grumble/grype"
)

// GrypeFile takes the path to a json file containing a grype
// report, and parses it.
func GrypeFile(path string) (*grype.Document, error) {
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return GrypeReport(rawJSON)
}

// GrypeReport takes the content of a json file
// and returns a parsed string
func GrypeReport(rawJSON []byte) (*grype.Document, error) {
	grypeDocument := &grype.Document{}

	err := json.Unmarshal(rawJSON, grypeDocument)
	if err != nil {
		return nil, err
	}

	return grypeDocument, nil
}
