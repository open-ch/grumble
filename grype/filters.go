package grype

// Filters holds all the filters to apply in a Filter() call
// to a given document
//
// TODO: Do we want this to be a all custom? or generic with
// arrays of string filters? Depends on what we want to filter?
type Filters struct {
	Severity string
}

// Filter applies the given filters and returns a new document
// containing only matches still matching.
// Note if no filters are defined the original document will be returned,
// not a copy.
func (d *Document) Filter(filters *Filters) *Document {
	if filters.Severity == "" {
		return d
	}

	// Make a shallow copy of all but matches
	fd := &Document{
		Descriptor: d.Descriptor,
		Source:     d.Source,
		Distro:     d.Distro,
	}

	// Filter matches to copy
	for _, match := range d.Matches {
		if match.Vulnerability.Severity == filters.Severity {
			fd.Matches = append(fd.Matches, match)
		}
	}

	return fd
}
