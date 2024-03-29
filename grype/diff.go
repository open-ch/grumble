package grype

import (
	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/ownership"
)

// DocumentDiff holds the difference between two documents limited to
// the matches. And further limited to added and removed matches
// match changes not supported.
type DocumentDiff struct {
	Added   []*Match `json:"added"`
	Removed []*Match `json:"removed"`
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

	for _, m := range sortedA.Matches {
		uid := m.UniqueID()
		_, existsBefore := lookupB[uid]
		if !existsBefore {
			diff.Added = append(diff.Added, enrichWithCodeowners(m))
		}
	}

	for _, m := range sortedB.Matches {
		uid := m.UniqueID()
		_, existsAfter := lookupA[uid]
		if !existsAfter {
			diff.Removed = append(diff.Removed, enrichWithCodeowners(m))
		}
	}

	return diff
}

func buildUniqueMatchKeyLookup(d *Document) map[string]*Match {
	lookup := map[string]*Match{}
	for _, m := range d.Matches {
		lookup[m.UniqueID()] = m
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
