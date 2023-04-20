package grype

import (
	"strings"
)

// Filters holds all the filters to apply in a Filter() call
// to a given document.
//   - Severity will filter by the value (Critical, Low, ...)
//   - FixState will filter by the value (unknown, fixed, not-fixed)
//   - PathPrefix will filter by whether or not the path starts with the given fragment
//     (could be exenteded with a glob based path filter)
type Filters struct {
	Severity   string
	FixState   string
	PathPrefix string
}

// Filter applies the given filters and returns a new document
// containing only matches still matching.
// Note if no filters are defined the original document will be returned,
// not a copy.
func (d *Document) Filter(filters *Filters) *Document {
	// Make a shallow copy of all but matches
	fd := &Document{
		Descriptor: d.Descriptor,
		Source:     d.Source,
		Distro:     d.Distro,
	}

	for _, match := range d.Matches {
		if filters.matchAllFor(&match) {
			fd.Matches = append(fd.Matches, match)
		}
	}

	return fd
}

func (f *Filters) matchAllFor(match *Match) bool {
	return f.bySeverity(match) && f.byFixState(match) && f.byPathPrefix(match)
}

func (f *Filters) bySeverity(match *Match) bool {
	return f.Severity == "" || match.Vulnerability.Severity == f.Severity
}

func (f *Filters) byFixState(match *Match) bool {
	return f.FixState == "" || match.Vulnerability.Fix.State == f.FixState
}

func (f *Filters) byPathPrefix(match *Match) bool {
	if f.PathPrefix == "" {
		return true
	}

	for _, location := range match.Artifact.Locations {
		if strings.HasPrefix(location.Path, f.PathPrefix) {
			return true
		}
	}

	return false
}
