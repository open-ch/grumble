//nolint:dupl // implements same interface, but is different
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
		return nil, fmt.Errorf("grumble cannot load Syft document: %w", err)
	}

	return SyftSBOM(rawJSON)
}

// SyftSBOM takes the content of a json file
// and returns a parsed string
func SyftSBOM(rawJSON []byte) (*syft.Document, error) {
	syftDocument := &syft.Document{}

	err := json.Unmarshal(rawJSON, syftDocument)
	if err != nil {
		return nil, fmt.Errorf("grumble cannot parse Syft document: %w", err)
	}

	return syftDocument, nil
}

// WriteSyftFile takes a syft document and a path and writes the document on disk in json format
func WriteSyftFile(document *syft.Document, path string) error {
	const permissions os.FileMode = 0600
	rawJSON, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("grumble cannot read Syft document: %w", err)
	}
	err = os.WriteFile(path, rawJSON, permissions)
	if err != nil {
		return fmt.Errorf("grumble cannot write Syft document: %w", err)
	}
	return nil
}
