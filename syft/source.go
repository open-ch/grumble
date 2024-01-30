package syft

// Source object represents the thing that was cataloged
type Source struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Metadata any    `json:"metadata"`
}
