package syft

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// Package represents a pkg.Package object specialized for JSON marshaling and unmarshalling.
type Package struct {
	PackageBasicData
	PackageCustomData
}

// PackageBasicData contains non-ambiguous values (type-wise) from pkg.Package.
type PackageBasicData struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Type      string    `json:"type"`
	FoundBy   string    `json:"foundBy"`
	Locations locations `json:"locations"`
	Licenses  licenses  `json:"licenses"`
	Language  string    `json:"language"`
	CPEs      cpes      `json:"cpes"`
	PURL      string    `json:"purl"`
}

type cpes []CPE

// CPE represents a Common Platform Enumeration, with the source that has generated it
type CPE struct {
	Value  string `json:"cpe"`
	Source string `json:"source,omitempty"`
}

type licenses []License

type locations []Location

// License represents a License of a package
type License struct {
	Value          string     `json:"value"`
	SPDXExpression string     `json:"spdxExpression"`
	Type           string     `json:"type"`
	URLs           []string   `json:"urls"`
	Locations      []Location `json:"locations"`
}

// PackageCustomData contains ambiguous values (type-wise) from pkg.Package.
type PackageCustomData struct {
	MetadataType string `json:"metadataType,omitempty"`
	Metadata     any    `json:"metadata,omitempty"`
}

func sourcedCPESfromSimpleCPEs(simpleCPEs []string) []CPE {
	var result = make([]CPE, 0, len(simpleCPEs))
	for _, s := range simpleCPEs {
		result = append(result, CPE{
			Value: s,
		})
	}
	return result
}

func (c *cpes) UnmarshalJSON(b []byte) error {
	var cs []CPE
	if err := json.Unmarshal(b, &cs); err != nil {
		var simpleCPEs []string
		if err := json.Unmarshal(b, &simpleCPEs); err != nil {
			return fmt.Errorf("unable to unmarshal cpes: %w", err)
		}
		cs = sourcedCPESfromSimpleCPEs(simpleCPEs)
	}
	*c = cs
	return nil
}

// UniqueID returns a string that uniquely identifies an artifact
// it's made of the ID and a digest of the artifact
// location paths.
func (m *Package) UniqueID() string {
	builder := strings.Builder{}
	for _, location := range m.Locations {
		_, _ = builder.WriteString(location.AccessPath)
	}
	locationDigest := sha256.Sum256([]byte(builder.String()))
	return fmt.Sprintf("%s:%s:%x", m.ID, m.PURL, locationDigest)
}
