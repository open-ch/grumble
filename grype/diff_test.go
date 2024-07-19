package grype

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var testMatchWithCodeowner = &Match{
	Vulnerability: Vulnerability{
		ID:       "low:cve1",
		Severity: "Low",
		Fix:      Fix{State: "fixed"},
	},
	Artifact: Artifact{
		Locations: []Location{{
			Path:       "example/path1/relevantFile",
			Codeowners: []string{"@org-name/example-team"},
		}},
		Purl: "pkg:golang/example.com/example@v1.0.0",
	},
}

func TestDiff(t *testing.T) {
	// Note: we can use the test matches from filters_test.go for now:
	// testMatches["low:cve1:fixed"],
	// testMatches["low:cve2:nopath"],
	// testMatches["high:cve1:fixed"],
	// testMatches["critical:cve1"],
	// testMatches["critical:cve2"],
	var tests = []struct {
		name         string
		before       *Document
		after        *Document
		expectedDiff *DocumentDiff
	}{
		{
			name:         "Empty empty documents have no differences",
			before:       &Document{},
			after:        &Document{},
			expectedDiff: &DocumentDiff{},
		},
		{
			name:   "Detect match in after only as added",
			before: &Document{},
			after:  &Document{Matches: []*Match{testMatches["low:cve1:fixed"]}},
			expectedDiff: &DocumentDiff{
				Added: []*Match{testMatchWithCodeowner},
			},
		},
		{
			name:   "Detect match in before only as removed",
			before: &Document{Matches: []*Match{testMatches["low:cve1:fixed"]}},
			after:  &Document{},
			expectedDiff: &DocumentDiff{
				Removed: []*Match{testMatchWithCodeowner},
			},
		},
		{
			name: "Detect mix of added and removed matches and sorted",
			before: &Document{Matches: []*Match{
				testMatches["low:cve2:nopath"],
				testMatches["high:cve1:fixed"],
				testMatches["critical:cve2"],
			}},
			after: &Document{Matches: []*Match{
				testMatches["low:cve1:fixed"],
				testMatches["high:cve1:fixed"],
				testMatches["critical:cve1"],
			}},
			expectedDiff: &DocumentDiff{
				Added: []*Match{
					testMatches["critical:cve1"],
					testMatches["low:cve1:fixed"],
				},
				Removed: []*Match{
					testMatches["critical:cve2"],
					testMatches["low:cve2:nopath"],
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			diff := Diff(tc.before, tc.after)

			assert.Equal(t, tc.expectedDiff, diff)
		})
	}
}

func TestDiffForUpdatedEntry(t *testing.T) {
	var tests = []struct {
		name         string
		before       *Document
		after        *Document
		expectedDiff *DocumentDiff
	}{
		{
			name:   "Detect match in after only as added",
			before: &Document{Matches: []*Match{testMatches["low:cve1:fixed"]}},
			after:  &Document{Matches: []*Match{testMatches["low:cve1:updated"]}},
			expectedDiff: &DocumentDiff{
				Added: []*Match{
					testMatches["low:cve1:updated"],
				},
				Removed: []*Match{
					testMatches["low:cve1:fixed"],
				},
			},
		}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			diff := Diff(tc.before, tc.after)

			assert.Equal(t, tc.expectedDiff, diff)
		})
	}
}
