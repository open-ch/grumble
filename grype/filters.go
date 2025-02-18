package grype

import (
	"strings"

	"github.com/open-ch/grumble/filters"
	"github.com/open-ch/grumble/ownership"

	"github.com/charmbracelet/log"
)

// Filter applies the given filters and returns a new document
// containing only matches still matching.
// Note if no filters are defined the original document will be returned,
// not a copy.
func (d *Document) Filter(filterValues *filters.Filters) *Document {
	// Make a shallow copy of all but matches
	fd := &Document{
		Descriptor:     d.Descriptor,
		IgnoredMatches: d.IgnoredMatches,
		Distro:         d.Distro,
		Source:         d.Source,
	}

	for _, m := range d.Matches {
		if MatchAllFor(filterValues, m) {
			fd.Matches = append(fd.Matches, m)
		}
	}

	return fd
}

// MatchAllFor returns true if all filters return true for the given Match object
func MatchAllFor(f *filters.Filters, match *Match) bool {
	return bySeverity(f, match) && byFixState(f, match) && byPathPrefix(f, match) && byCodeowners(f, match)
}

func byCodeowners(f *filters.Filters, match *Match) bool {
	if f.Codeowners == "" {
		return true
	}
	if match == nil {
		return false
	}

	ownedByOneOf := strings.Split(f.Codeowners, filters.FilterSeparator)

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

func bySeverity(f *filters.Filters, match *Match) bool {
	if f.Severity == "" {
		// empty severity returns true -> do not change matches, even if nil
		return true
	}
	if match == nil {
		// severity check cannot be done on nil match. return false.
		return false
	}
	if match.Vulnerability.Severity == f.Severity {
		return true
	}

	if strings.Contains(f.Severity, filters.FilterSeparator) {
		// Note: this might get expensive if we need to split for every match
		// on a large token set. We could either preprocess the severity
		// or use a regex which we compile once.
		for _, severity := range strings.Split(f.Severity, filters.FilterSeparator) {
			if match.Vulnerability.Severity == severity {
				return true
			}
		}
	}

	return false
}

func byFixState(f *filters.Filters, match *Match) bool {
	if f.FixState == "" {
		return true
	}
	if match == nil {
		return false
	}
	if match.Vulnerability.Fix.State == f.FixState {
		return true
	}

	if strings.Contains(f.FixState, filters.FilterSeparator) {
		// Note: this might get expensive if we need to split for every match
		// on a large token set. We could either preprocess the severity
		// or use a regex which we compile once.
		for _, fixState := range strings.Split(f.FixState, filters.FilterSeparator) {
			if match.Vulnerability.Fix.State == fixState {
				return true
			}
		}
	}

	return false
}

func byPathPrefix(f *filters.Filters, match *Match) bool {
	if f.PathPrefix == "" {
		return true
	}
	if match == nil {
		return false
	}

	var targetPaths = strings.Split(f.PathPrefix, filters.FilterSeparator)
	for _, pathPrefix := range targetPaths {
		for _, location := range match.Artifact.Locations {
			if strings.HasPrefix(location.Path, pathPrefix) {
				return true
			}
		}
	}

	return false
}
