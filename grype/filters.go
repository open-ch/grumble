package grype

import (
	"strings"

	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/ownership"
)

// Filters holds all the filters to apply in a Filter() call
// to a given document.
//   - Severity will filter by the value (Critical, Low, ...)
//   - FixState will filter by the value (unknown, fixed, not-fixed)
//   - PathPrefix will filter by whether or not the path starts with the given fragment
//     (could be exenteded with a glob based path filter)
//   - Codeowners will filter by the codeowners that match a given path
type Filters struct {
	Severity   string
	FixState   string
	PathPrefix string
	Codeowners string
}

const filterSeparator = ","

// Filter applies the given filters and returns a new document
// containing only matches still matching.
// Note if no filters are defined the original document will be returned,
// not a copy.
func (d *Document) Filter(filters *Filters) *Document {
	// Make a shallow copy of all but matches
	fd := &Document{
		Descriptor:     d.Descriptor,
		IgnoredMatches: d.IgnoredMatches,
		Distro:         d.Distro,
		Source:         d.Source,
	}

	for i := range d.Matches {
		if filters.MatchAllFor(&d.Matches[i]) {
			fd.Matches = append(fd.Matches, d.Matches[i])
		}
	}

	return fd
}

// MatchAllFor returns true if all filters return true for the given Match object
func (f *Filters) MatchAllFor(match *Match) bool {
	return f.bySeverity(match) && f.byFixState(match) && f.byPathPrefix(match) && f.byCodeowners(match)
}

func (f *Filters) byCodeowners(match *Match) bool {
	if f.Codeowners == "" {
		return true
	}

	ownedByOneOf := strings.Split(f.Codeowners, filterSeparator)

	for _, location := range match.Artifact.Locations {
		owned, err := ownership.IsOwnedBy(location.Path, ownedByOneOf)
		if err != nil {
			log.Error("unable to look up codeowners for path")
			return false
		}
		if owned {
			return owned
		}
	}

	return false
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
