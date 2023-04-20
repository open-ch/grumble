package grype

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testMatches map[string]Match = map[string]Match{
	"low:cve1": Match{
		Vulnerability: Vulnerability{
			Severity: "Critical",
		},
	},
	"critical:cve1": Match{
		Vulnerability: Vulnerability{
			Severity: "Critical",
		},
	},
}
var testDocumentAllMatches Document = Document{
	Matches: []Match{
		testMatches["critical:cve1"],
	},
}

func TestFilter(t *testing.T) {
	var tests = []struct {
		name            string
		document        *Document
		expectedMatches []Match
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
			expectedMatches: []Match{
				testMatches["critical:cve1"],
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filteredDoc := tc.document.Filter(&tc.filters)

			assert.Equal(t, tc.expectedMatches, filteredDoc.Matches)
		})
	}
}
