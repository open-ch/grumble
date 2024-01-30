package syft

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
	Locations locations `json:"locations"` // WAS NOT LIKE THAT, WAS A STRUCT
	Licenses  licenses  `json:"licenses"`
	Language  string    `json:"language"`
	CPEs      []string  `json:"cpes"`
	PURL      string    `json:"purl"`
}

type licenses []License

type locations []Location

// License represents a License of a package
type License struct {
	Value          string     `json:"value"`
	SPDXExpression string     `json:"spdxExpression"`
	Type           string     `json:"type"`
	URLs           []string   `json:"urls"`
	Locations      []Location `json:"locations"` // WAS NOT LIKE THAT, WAS A STRUCT
}

// PackageCustomData contains ambiguous values (type-wise) from pkg.Package.
type PackageCustomData struct {
	MetadataType string `json:"metadataType,omitempty"`
	Metadata     any    `json:"metadata,omitempty"`
}
