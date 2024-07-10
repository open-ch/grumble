package grype

// golangci-lint: mnd

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
		return compareMatches(sd.Matches[i], sd.Matches[j])
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

// None Negligible Low Medium High Critical are the possible severity values for vulnerabilities
const (
	None = iota
	Negligible
	Low
	Medium
	High
	Critical
)

func getNumericalSeverity(severity string) int {
	switch severity {
	case "Critical":
		return Critical
	case "High":
		return High
	case "Medium":
		return Medium
	case "Low":
		return Low
	case "Negligible":
		return Negligible
	}
	return None
}
