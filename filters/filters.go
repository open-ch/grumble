package filters

import (
	"errors"
	"fmt"
	"slices"
	"strings"

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

// FilterSeparator is the separator used to split filter values
const FilterSeparator = ","

// Validate returns a list of errors if any filter expression
// is misspelled or could never match.
// This guards against false positives if users have typos in their filters.
func Validate(f *Filters) []error {
	var errorList []error
	tests := []struct {
		content string
		name    string
		allowed []string
	}{
		{f.FixState, FixState, []string{"unknown", "not-fixed", "fixed"}},
		{f.Severity, Severity, []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}},
		{f.Codeowners, Codeowners, ownership.GetCodeowners()},
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
		if s != "" && !slices.Contains(allowed, s) {
			msg := fmt.Sprintf("%s: invalid filter: %s is not in %s", name, s, allowed)
			errorList = append(errorList, errors.New(msg))
		}
	}
	return errorList
}
