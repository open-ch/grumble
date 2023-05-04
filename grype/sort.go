package grype

import (
	"sort"
)

// Sort returns a new shallow copy of a document with the matches sorted
// by multiple keys as follows:
// - severity
// - CVE
// - Path
func (d *Document) Sort() *Document {
	sd := &Document{
		Descriptor:     d.Descriptor,
		Distro:         d.Distro,
		IgnoredMatches: d.IgnoredMatches,
		Source:         d.Source,
	}
	sd.Matches = append(sd.Matches, d.Matches...)

	sort.Slice(sd.Matches, func(i, j int) bool {
		return compareMatches(&sd.Matches[i], &sd.Matches[j])
	})

	return sd
}

// compareMatches is a sort helper it compares 2 values
// and retursn true if j is smaller than i.
// The goal is to sort over multiple keys:
// Severity first (enum)
// Then CVE (string)
// Then Path (string)
func compareMatches(i, j *Match) bool {
	iSeverity := getNumericalSeverity(i.Vulnerability.Severity)
	jSeverity := getNumericalSeverity(j.Vulnerability.Severity)

	if iSeverity != jSeverity {
		return iSeverity > jSeverity
	}

	if i.Vulnerability.ID != j.Vulnerability.ID {
		return i.Vulnerability.ID > j.Vulnerability.ID
	}

	return i.Artifact.Purl > j.Artifact.Purl
}

func getNumericalSeverity(severity string) int {
	switch severity {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Negligible":
		return 1
	}
	return 0
}
