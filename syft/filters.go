package syft

import (
	"github.com/open-ch/grumble/filters"
	"github.com/open-ch/grumble/ownership"
	"strings"

	"github.com/charmbracelet/log"
)

// Match a syft match could be a file, a package or a relationship
type Match interface {
	File | Package | Relationship
}

// Filter applies the given filters and returns a new document
// containing only matches still matching.
// Note if no filters are defined the original document will be returned,
// not a copy.
func (d *Document) Filter(filtersValues *filters.Filters) *Document {
	// Make a shallow copy of all but matches
	fd := &Document{
		Descriptor:            d.Descriptor,
		Files:                 []File{},
		Artifacts:             []Package{},
		ArtifactRelationships: []Relationship{},
		Distro:                d.Distro,
		Source:                d.Source,
	}

	if filtersValues.Severity != "" {
		log.Debug("Filtering by severity is not supported for Syft documents", "severity", filtersValues.Severity)
		filtersValues.Severity = ""
		return fd
	}

	if filtersValues.FixState != "" {
		log.Debug("Filtering by fix-state is not supported for Syft documents", "fix-state", filtersValues.FixState)
		filtersValues.FixState = ""
		return fd
	}

	for _, m := range d.Files {
		if MatchAllFor(filtersValues, m) {
			fd.Files = append(fd.Files, m)
		}
	}

	for i := range d.Artifacts {
		if MatchAllFor(filtersValues, d.Artifacts[i]) {
			fd.Artifacts = append(fd.Artifacts, d.Artifacts[i])
		}
	}

	return fd
}

// MatchAllFor returns true if all filters return true for the given Match object
func MatchAllFor[T Match](filtersValues *filters.Filters, match T) bool {
	return byPathPrefix(filtersValues, match) && byCodeowners(filtersValues, match)
}

func byCodeowners[T Match](filtersValues *filters.Filters, match T) bool {
	if filtersValues.Codeowners == "" {
		return true
	}

	ownedByOneOf := strings.Split(filtersValues.Codeowners, filters.FilterSeparator)

	switch castedMatch := any(match).(type) {
	case File:
		owned, err := ownership.IsOwnedBy(castedMatch.Location.RealPath, ownedByOneOf)
		if err != nil {
			log.Error("unable to look up codeowners for path")
			return false
		}
		return owned
	case Package:
		for _, location := range castedMatch.Locations {
			owned, err := ownership.IsOwnedBy(location.AccessPath, ownedByOneOf)
			if err != nil {
				log.Errorf("unable to look up codeowners for path: %s", location.AccessPath)
				return false
			}
			if owned {
				return owned
			}
		}
	}

	return false
}

func byPathPrefix[T Match](filtersValues *filters.Filters, match T) bool {
	if filtersValues.PathPrefix == "" {
		return true
	}

	var targetPaths = strings.Split(filtersValues.PathPrefix, filters.FilterSeparator)
	for _, pathPrefix := range targetPaths {
		switch castedMatch := any(match).(type) {
		case File:
			if strings.HasPrefix(castedMatch.Location.RealPath, pathPrefix) {
				return true
			}
		case Package:
			for _, location := range castedMatch.Locations {
				if strings.HasPrefix(location.AccessPath, pathPrefix) {
					return true
				}
			}
		}
	}
	return false
}
