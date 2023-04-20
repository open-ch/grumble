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

const filterSeparator = ","

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
	if f.Severity == "" || match.Vulnerability.Severity == f.Severity {
		return true
	}

	if strings.Contains(f.Severity, filterSeparator) {
		// Note: this might get expensive if we need to split for every match
		// on a large token set. We could either preprocess the severity
		// or use a regex which we compile once.
		for _, severity := range strings.Split(f.Severity, filterSeparator) {
			if match.Vulnerability.Severity == severity {
				return true
			}
		}
	}

	return false
}

func (f *Filters) byFixState(match *Match) bool {
	if f.FixState == "" || match.Vulnerability.Fix.State == f.FixState {
		return true
	}

	if strings.Contains(f.FixState, filterSeparator) {
		// Note: this might get expensive if we need to split for every match
		// on a large token set. We could either preprocess the severity
		// or use a regex which we compile once.
		for _, fixState := range strings.Split(f.FixState, filterSeparator) {
			if match.Vulnerability.Fix.State == fixState {
				return true
			}
		}
	}

	return false
}

func (f *Filters) byPathPrefix(match *Match) bool {
	if f.PathPrefix == "" {
		return true
	}

	if strings.Contains(f.PathPrefix, filterSeparator) {
		// Note: this might get expensive if we need to split for every match
		// on a large token set. We could either preprocess the severity
		// or use a regex which we compile once.
		for _, pathPrefix := range strings.Split(f.PathPrefix, filterSeparator) {
			for _, location := range match.Artifact.Locations {
				if strings.HasPrefix(location.Path, pathPrefix) {
					return true
				}
			}
		}
	}

	for _, location := range match.Artifact.Locations {
		if strings.HasPrefix(location.Path, f.PathPrefix) {
			return true
		}
	}

	return false
}
