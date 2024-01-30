package syft

// File is a struct that represents a specific file that has been scanned
type File struct {
	ID       string             `json:"id"`
	Location Coordinates        `json:"location"`
	Metadata *FileMetadataEntry `json:"metadata,omitempty"`
	Contents string             `json:"contents,omitempty"`
	Digests  []Digest           `json:"digests,omitempty"`
	Licenses []FileLicense      `json:"licenses,omitempty"`
}

// Coordinates represents the coordinates for a file. Imported from file.Coordinates in syft
type Coordinates struct {
	RealPath     string `json:"path"`              // The path where all path ancestors have no hardlinks / symlinks
	FileSystemID string `json:"layerID,omitempty"` // An ID representing the filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank.
}

// FileMetadataEntry metadata associated to a file
type FileMetadataEntry struct {
	Mode            int    `json:"mode"`
	Type            string `json:"type"`
	LinkDestination string `json:"linkDestination,omitempty"`
	UserID          int    `json:"userID"`
	GroupID         int    `json:"groupID"`
	MIMEType        string `json:"mimeType"`
	Size            int64  `json:"size"`
}

// FileLicense represents a license associated to a file
type FileLicense struct {
	Value          string               `json:"value"`
	SPDXExpression string               `json:"spdxExpression"`
	Type           string               `json:"type"` // converted from license.Type
	Evidence       *FileLicenseEvidence `json:"evidence,omitempty"`
}

// FileLicenseEvidence represents the evidence associated to a file license
type FileLicenseEvidence struct {
	Confidence int `json:"confidence"`
	Offset     int `json:"offset"`
	Extent     int `json:"extent"`
}

// Digest represents a file digest. Imported from file.Digest in syft
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
