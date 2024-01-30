package syft

// Relationship is a struct that represents the relationships between packages.
type Relationship struct {
	Parent   string `json:"parent"`
	Child    string `json:"child"`
	Type     string `json:"type"`
	Metadata any    `json:"metadata,omitempty"`
}
