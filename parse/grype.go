package parse

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-ch/grumble/grype"
)

// GrypeFile takes the path to a json file containing a grype
// report, and parses it.
func GrypeFile(path string) (*grype.Document, error) {
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grumble cannot load document: %w", err)
	}

	return GrypeReport(rawJSON)
}

// GrypeReport takes the content of a json file
// and returns a parsed string
func GrypeReport(rawJSON []byte) (*grype.Document, error) {
	grypeDocument := &grype.Document{}

	err := json.Unmarshal(rawJSON, grypeDocument)
	if err != nil {
		return nil, fmt.Errorf("grumble cannot parse document: %w", err)
	}

	return grypeDocument, nil
}
