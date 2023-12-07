package grype

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"

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

// Filter Flags enums for the CLI and config keys
const (
	FixState   = "fix-state"
	PathPrefix = "path-prefix"
	Severity   = "severity"
	Codeowners = "codeowners"
)

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

	for _, m := range d.Matches {
		if filters.MatchAllFor(m) {
			fd.Matches = append(fd.Matches, m)
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
	if match == nil {
		return false
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
	if f.FixState == "" {
		return true
	}
	if match == nil {
		return false
	}
	if match.Vulnerability.Fix.State == f.FixState {
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
	if match == nil {
		return false
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

// Validate returns a list of errors if any filter expression
// is misspelled or could never match.
// This guards against false positives if users have typos in their filters.
func (f *Filters) Validate() []error {
	var errorList []error
	tests := []struct {
		content string
		name    string
		allowed []string
	}{
		{f.FixState, FixState, []string{"unknown", "not-fixed", "fixed"}},
		{f.Severity, Severity, []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}},
		{f.Codeowners, Codeowners, getCodeowners()},
	}
	for i := range tests {
		newErrors := validateField(tests[i].name, tests[i].content, tests[i].allowed)
		if newErrors != nil {
			errorList = append(errorList, newErrors...)
		}
	}
	return errorList
}

func validateField(name, input string, allowed []string) []error {
	in := strings.Split(input, ",")
	var errorList []error
	for _, s := range in {
		if s != "" && !sliceContains(allowed, s) {
			msg := fmt.Sprintf("%s: invalid filter: %s is not in %s", name, s, allowed)
			errorList = append(errorList, errors.New(msg))
		}
	}
	return errorList
}

func getCodeowners() []string {
	codeownersPath := viper.GetString("codeownersPath")
	repositoryPath := viper.GetString("repositoryPath")
	if repositoryPath != "" {
		codeownersPath = path.Join(repositoryPath, codeownersPath)
	}
	cmd := fmt.Sprintf("awk '{print $2}' %s | grep '^@' | sort | uniq", codeownersPath)
	log.Debugf("extracting codeowners with command=%s", cmd)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		log.Error(err)
		return nil
	}
	owners := strings.Split(string(out), "\n")
	log.Debugf("found %d codeowner entries", len(owners))
	return owners
}

func sliceContains(s []string, str string) bool {
	// from Go 1.21.0 on, use slices.Contains() instead!
	// how nice it would be to use a high level language... ¯\_(ツ)_/¯
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
