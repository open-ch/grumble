package grype

import (
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var testMatches = map[string]*Match{
	"low:cve1:fixed": {
		Vulnerability: Vulnerability{
			ID:       "low:cve1",
			Severity: "Low",
			Fix:      Fix{State: "fixed"},
		},
		Artifact: Artifact{
			Locations: []Location{{Path: "example/path1/relevantFile"}},
			Purl:      "pkg:golang/example.com/example@v1.0.0",
		},
	},
	"low:cve2:nopath": {
		Vulnerability: Vulnerability{
			ID:       "low:cve2",
			Severity: "Low",
			Fix:      Fix{State: "unknown"},
		},
	},
	"high:cve1:fixed": {
		Vulnerability: Vulnerability{
			ID:       "high:cve1",
			Severity: "High",
			Fix:      Fix{State: "fixed"},
		},
		Artifact: Artifact{
			Locations: []Location{{Path: "example/path2/relevantFile"}},
		},
	},
	"critical:cve1": {
		Vulnerability: Vulnerability{
			ID:       "critical:cve1",
			Severity: "Critical",
			Fix:      Fix{State: "not-fixed"},
		},
		Artifact: Artifact{
			Locations: []Location{{Path: "example/path3/relevantFile"}},
		},
	},
	"critical:cve2": {
		Vulnerability: Vulnerability{
			ID:       "critical:cve2",
			Severity: "Critical",
			Fix:      Fix{State: "unknown"},
		},
		Artifact: Artifact{
			Locations: []Location{
				{Path: "example/path4/relevantFile"},
				{Path: "other/path1/relevantFile"},
			},
		},
	},
}
var testDocumentAllMatches = Document{
	Matches: []*Match{
		testMatches["low:cve1"],
		testMatches["low:cve2"],
		testMatches["critical:cve1"],
		testMatches["critical:cve2"],
	},
}

func TestFilter(t *testing.T) {
	var tests = []struct {
		name            string
		document        *Document
		expectedMatches []*Match
		filters         Filters
	}{
		{
			name:     "Empty filters return empty document empty results",
			document: &Document{},
		},
		{
			name:            "Empty filters return all matches in document",
			document:        &testDocumentAllMatches,
			expectedMatches: testDocumentAllMatches.Matches,
		},
		{
			name:     "Severity filter nothing for medium",
			document: &testDocumentAllMatches,
			filters:  Filters{Severity: "Medium"},
		},
		{
			name:     "Severity filter all for critical",
			document: &testDocumentAllMatches,
			filters:  Filters{Severity: "Critical"},
			expectedMatches: []*Match{
				testMatches["critical:cve1"],
				testMatches["critical:cve2"],
			},
		},
		{
			name:     "Severity+Path+Fix filter each multiple values",
			document: &testDocumentAllMatches,
			filters:  Filters{FixState: "invalid,unknown", Severity: "High,Critical", PathPrefix: "wrong/,other/"},
			expectedMatches: []*Match{
				testMatches["critical:cve2"],
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			filteredDoc := tc.document.Filter(&tc.filters)

			assert.Equal(t, tc.expectedMatches, filteredDoc.Matches)
		})
	}
}

func TestMatchAllFor(t *testing.T) {
	var tests = []struct {
		name        string
		filters     Filters
		match       *Match
		expectMatch bool
	}{
		{
			name:        "Empty filter matches",
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Single FixState filter match",
			match:       testMatches["high:cve1:fixed"],
			filters:     Filters{FixState: "fixed"},
			expectMatch: true,
		},
		{
			name:    "Single FixState filter mismatch",
			match:   testMatches["high:cve1:fixed"],
			filters: Filters{FixState: "unknown"},
		},
		{
			name:        "Single Severity filter match",
			match:       testMatches["high:cve1:fixed"],
			filters:     Filters{Severity: "High"},
			expectMatch: true,
		},
		{
			name:    "Single Severity filter mismatch",
			match:   testMatches["high:cve1:fixed"],
			filters: Filters{Severity: "Low"},
		},
		{
			name:        "Single PathPrefix filter match",
			match:       testMatches["high:cve1:fixed"],
			filters:     Filters{PathPrefix: "example/path"},
			expectMatch: true,
		},
		{
			name:    "Single PathPrefix filter mismatch",
			match:   testMatches["high:cve1:fixed"],
			filters: Filters{PathPrefix: "other/path"},
		},
		{
			name:        "Dual FixState+Severity filter match",
			match:       testMatches["high:cve1:fixed"],
			filters:     Filters{FixState: "fixed", Severity: "High"},
			expectMatch: true,
		},
		{
			name:    "Dual FixState+Severity filter mismatch",
			match:   testMatches["high:cve1:fixed"],
			filters: Filters{FixState: "fixed", Severity: "Low"},
		},
		{
			name:        "Triple PathPrefix+FixState+Severity filter match",
			match:       testMatches["high:cve1:fixed"],
			filters:     Filters{PathPrefix: "example/", FixState: "fixed", Severity: "High"},
			expectMatch: true,
		},
		{
			name:    "Triple PathPrefix+FixState+Severity filter mismatch",
			match:   testMatches["high:cve1:fixed"],
			filters: Filters{PathPrefix: "other/", FixState: "fixed", Severity: "Low"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := tc.filters.MatchAllFor(tc.match)

			assert.Equal(t, tc.expectMatch, matched)
		})
	}
}

func TestByCodeowners(t *testing.T) {
	var tests = []struct {
		name        string
		filters     Filters
		match       *Match
		expectMatch bool
	}{
		{
			name:        "Empty filter matches",
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches single owners",
			filters:     Filters{Codeowners: "@org-name/example-team"},
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches one of several owners",
			filters:     Filters{Codeowners: "@org-name/example-team,@org-name/other-team"},
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:    "Missmatch non-owners team",
			filters: Filters{Codeowners: "@org-name/other-team"},
			match:   testMatches["critical:cve1"],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			matched := tc.filters.byCodeowners(tc.match)

			assert.Equal(t, tc.expectMatch, matched)
		})
	}
}

func TestBySeverity(t *testing.T) {
	var tests = []struct {
		name        string
		filters     Filters
		match       *Match
		expectMatch bool
	}{
		{
			name:        "Empty filter matches",
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches severity",
			filters:     Filters{Severity: "Critical"},
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches first of multiple severities",
			filters:     Filters{Severity: "Critical,High"},
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches second of multiple severities",
			filters:     Filters{Severity: "Critical,High,Medium"},
			match:       testMatches["high:cve1:fixed"],
			expectMatch: true,
		},
		{
			name:    "Missmatch severity differs",
			filters: Filters{Severity: "High"},
			match:   testMatches["critical:cve1"],
		},
		{
			name:    "Missmatch no common severity out of multiple",
			filters: Filters{Severity: "Critical,High"},
			match:   testMatches["low:cve1:fixed"],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := tc.filters.bySeverity(tc.match)

			assert.Equal(t, tc.expectMatch, matched)
		})
	}
}

func TestByFixState(t *testing.T) {
	var tests = []struct {
		name        string
		fixState    string
		match       *Match
		expectMatch bool
	}{
		{
			name:        "Empty filter matches",
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Check for fixed",
			fixState:    "fixed",
			match:       testMatches["high:cve1:fixed"],
			expectMatch: true,
		},
		{
			name:        "Check for multiple states",
			fixState:    "unknown,fixed",
			match:       testMatches["high:cve1:fixed"],
			expectMatch: true,
		},
		{
			name:        "Check for unknown",
			fixState:    "unknown",
			match:       testMatches["critical:cve2"],
			expectMatch: true,
		},
		{
			name:        "Check for not-fixed",
			fixState:    "not-fixed",
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:     "Doesn't match invalid state",
			fixState: "invalid",
			match:    testMatches["high:cve1:fixed"],
		},
		{
			name:     "Doesn't match different state",
			fixState: "unknown",
			match:    testMatches["high:cve1:fixed"],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			filters := Filters{FixState: tc.fixState}
			matched := filters.byFixState(tc.match)

			assert.Equal(t, tc.expectMatch, matched)
		})
	}
}

func TestByPathPrefix(t *testing.T) {
	var tests = []struct {
		name        string
		filters     Filters
		match       *Match
		expectMatch bool
	}{
		{
			name:        "Empty filter matches",
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches with path prefix matches",
			filters:     Filters{PathPrefix: "example/path3/"},
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches with path prefix matches broadly",
			filters:     Filters{PathPrefix: "example/path"},
			match:       testMatches["critical:cve1"],
			expectMatch: true,
		},
		{
			name:        "Matches with non primary location",
			filters:     Filters{PathPrefix: "other/path1/"},
			match:       testMatches["critical:cve2"],
			expectMatch: true,
		},
		{
			name:        "Matches any of multiple csv pathprefixes",
			filters:     Filters{PathPrefix: "wrong/path1,other/path1/"},
			match:       testMatches["critical:cve2"],
			expectMatch: true,
		},
		{
			name:    "Missmatch when single location different",
			filters: Filters{PathPrefix: "example/path1/"},
			match:   testMatches["critical:cve1"],
		},
		{
			name:    "Missmatch when locations empty",
			filters: Filters{PathPrefix: "example/path1/"},
			match:   testMatches["low:cve2:nopath"],
		},
		{
			name:    "Missmatch when no location matches",
			filters: Filters{PathPrefix: "magical/path/"},
			match:   testMatches["critical:cve2"],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := tc.filters.byPathPrefix(tc.match)

			assert.Equal(t, tc.expectMatch, matched)
		})
	}
}

func TestFilterValidation(t *testing.T) {
	var tests = []struct {
		name           string
		filters        Filters
		expectedResult []error
	}{
		{
			name:           "Valid severity",
			filters:        Filters{Severity: "Negligible"},
			expectedResult: nil,
		},
		{
			name:           "Invalid severity",
			filters:        Filters{Severity: "Super"},
			expectedResult: []error{errors.New("severity: invalid filter: Super is not in [Critical High Medium Low Negligible Unknown]")},
		},
		{
			name:           "Invalid lowercase severity",
			filters:        Filters{Severity: "critical"},
			expectedResult: []error{errors.New("severity: invalid filter: critical is not in [Critical High Medium Low Negligible Unknown]")},
		},
		{
			name:           "Invalid separator",
			filters:        Filters{Severity: "Critical.High"},
			expectedResult: []error{errors.New("severity: invalid filter: Critical.High is not in [Critical High Medium Low Negligible Unknown]")},
		},
		{
			name:           "Valid separator",
			filters:        Filters{Severity: "Medium,Low"},
			expectedResult: nil,
		},
		{
			name:           "Valid fix state fixed",
			filters:        Filters{FixState: "fixed"},
			expectedResult: nil,
		},
		{
			name:           "Valid fix state not-fixed",
			filters:        Filters{FixState: "not-fixed"},
			expectedResult: nil,
		},
		{
			name:           "Invalid fix state notfixed",
			filters:        Filters{FixState: "notfixed"},
			expectedResult: []error{errors.New("fix-state: invalid filter: notfixed is not in [unknown not-fixed fixed]")},
		},
		{
			name:           "Valid combination fix state unknown,fixed",
			filters:        Filters{FixState: "unknown,fixed"},
			expectedResult: nil,
		},
		{
			name:           "Valid all fixed states",
			filters:        Filters{FixState: "not-fixed,unknown,fixed"},
			expectedResult: nil,
		},
		{
			name:           "Valid combinations fix state and severity",
			filters:        Filters{FixState: "not-fixed", Severity: "Critical,High,Medium"},
			expectedResult: nil,
		},
		{
			name:           "Valid codeowners",
			filters:        Filters{Codeowners: "@org-name/example-team"},
			expectedResult: nil,
		},
		{
			name:           "Invalid codeowners",
			filters:        Filters{Codeowners: "@org-name/true-heroes"},
			expectedResult: []error{errors.New("codeowners: invalid filter: @org-name/true-heroes is not in [@org-name/example-team ]")},
		},
		{
			name:           "Valid combinations fix state, severity and codeowners",
			filters:        Filters{FixState: "unknown", Severity: "Low,Unknown", Codeowners: "@org-name/example-team"},
			expectedResult: nil,
		},
		{
			name:    "Multiple errors to report",
			filters: Filters{FixState: "maybe", Severity: "Uncommon", Codeowners: "@org-name/example-tam"},
			expectedResult: []error{
				errors.New("fix-state: invalid filter: maybe is not in [unknown not-fixed fixed]"),
				errors.New("severity: invalid filter: Uncommon is not in [Critical High Medium Low Negligible Unknown]"),
				errors.New("codeowners: invalid filter: @org-name/example-tam is not in [@org-name/example-team ]"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.filters.Validate()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}
