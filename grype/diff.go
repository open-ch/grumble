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
func Diff(before, after *Document) (diff *DocumentDiff) {
	diff = &DocumentDiff{}

	sortedB := before.Sort()
	sortedA := after.Sort()

	lookupB := buildUniqueMatchKeyLookup(sortedB)
	lookupA := buildUniqueMatchKeyLookup(sortedA)

	for i := range sortedA.Matches {
		uid := sortedA.Matches[i].UniqueID()
		_, existsBefore := lookupB[uid]
		if !existsBefore {
			diff.Added = append(diff.Added, *enrichWithCodeowners(&sortedA.Matches[i]))
		}
	}

	for i := range sortedB.Matches {
		uid := sortedB.Matches[i].UniqueID()
		_, existsAfter := lookupA[uid]
		if !existsAfter {
			diff.Removed = append(diff.Removed, *enrichWithCodeowners(&sortedB.Matches[i]))
		}
	}

	return diff
}

func buildUniqueMatchKeyLookup(d *Document) map[string]Match {
	lookup := map[string]Match{}
	for i := range d.Matches {
		lookup[d.Matches[i].UniqueID()] = d.Matches[i]
	}
	return lookup
}

func enrichWithCodeowners(match *Match) *Match {
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
