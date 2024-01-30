package syft

// Secrets is a struct that represents the output of a secrets scan.
type Secrets struct {
	Location Coordinates    `json:"location"` // from file.Coordinates
	Secrets  []SearchResult `json:"secrets"`  // from file.SearchResult
}

// SearchResult is a struct that represents the result of a secrets scan.
type SearchResult struct {
	Classification string `json:"classification"`
	LineNumber     int64  `json:"lineNumber"`
	LineOffset     int64  `json:"lineOffset"`
	SeekPosition   int64  `json:"seekPosition"`
	Length         int64  `json:"length"`
	Value          string `json:"value,omitempty"`
}
