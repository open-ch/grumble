package grype

import (
	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/ownership"
)

// DocumentDiff holds the difference between two documents limited to
// the matches. And further limited to added and removed matches
// match changes not supported.
type DocumentDiff struct {
	Added   []Match `json:"added"`
	Removed []Match `json:"removed"`
}

// Diff takes 2 reports and returns the difference between them
// for vulnerabilities. This is limited to added and removed.
// Vulnerabilities are considered unique by combining:
func Diff(before *Document, after *Document) (diff *DocumentDiff) {
	diff = &DocumentDiff{}

	sortedB := before.Sort()
	sortedA := after.Sort()

	lookupB := buildUniqueMatchKeyLookup(sortedB)
	lookupA := buildUniqueMatchKeyLookup(sortedA)

	for _, match := range sortedA.Matches {
		uid := match.UniqueID()
		_, existsBefore := lookupB[uid]
		if !existsBefore {
			diff.Added = append(diff.Added, enrichWithCodeowners(match))
		}
	}

	for _, match := range sortedB.Matches {
		uid := match.UniqueID()
		_, existsAfter := lookupA[uid]
		if !existsAfter {
			diff.Removed = append(diff.Removed, enrichWithCodeowners(match))
		}
	}

	return diff
}

func buildUniqueMatchKeyLookup(d *Document) map[string]Match {
	lookup := map[string]Match{}
	for _, match := range d.Matches {
		lookup[match.UniqueID()] = match
	}
	return lookup
}

func enrichWithCodeowners(match Match) Match {
	for i, location := range match.Artifact.Locations {
		codeowners, err := ownership.LookupFor(location.Path)
		if err != nil {
			log.Warn("Error looking up codeowners: %s", err)
			codeowners = []string{"unavailable"}
		}
		match.Artifact.Locations[i].Codeowners = codeowners
	}
	return match
}
