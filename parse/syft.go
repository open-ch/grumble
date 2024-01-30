package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"github.com/open-ch/grumble/syft"
)

// SyftFile takes the path to a json file containing a syft
// sbom, and parses it.
func SyftFile(path string) (*syft.Document, error) {
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grumble cannot load document: %w", err)
	}

	return SyftSBOM(rawJSON)
}

// SyftSBOM takes the content of a json file
// and returns a parsed string
func SyftSBOM(rawJSON []byte) (*syft.Document, error) {
	syftDocument := &syft.Document{}

	err := json.Unmarshal(rawJSON, syftDocument)
	if err != nil {
		return nil, fmt.Errorf("grumble cannot parse document: %w", err)
	}

	return syftDocument, nil
}
