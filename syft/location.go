package syft

// Location represents a path relative to a particular filesystem resolved to a specific file.Reference. This struct is used as a key
// in content fetching to uniquely identify a file relative to a request (the AccessPath).
type Location struct {
	LocationData     `cyclonedx:""`
	LocationMetadata `cyclonedx:""`
}

// LocationData is a struct that represents the location of a file.
type LocationData struct {
	Coordinates `cyclonedx:""` // Empty string here means there is no intermediate property name, e.g. syft:locations:0:path without "coordinates"
	// note: it is IMPORTANT to ignore anything but the coordinates for a Location when considering the ID (hash value)
	// since the coordinates are the minimally correct ID for a location (symlinks should not come into play)
	AccessPath string    `hash:"ignore" json:"accessPath"` // The path to the file which may or may not have hardlinks / symlinks
	Ref        Reference `hash:"ignore"`                   // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

// Reference The file reference relative to the stereoscope.FileCatalog that has more information about this location. Imported from https://github.com/anchore/stereoscope/blob/main/pkg/file/reference.go
func (l LocationData) Reference() Reference {
	return l.Ref
}

// LocationMetadata is a struct that represents the metadata associated to a location.
type LocationMetadata struct {
	Annotations map[string]string `json:"annotations,omitempty"` // Arbitrary key-value pairs that can be used to annotate a location
}

// Reference ported from https://github.com/anchore/stereoscope/blob/main/pkg/file/reference.go
type Reference struct {
	id       uint64 //nolint:unused
	RealPath string
}
