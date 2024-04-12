package filters

import (
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

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
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			result := Validate(&tc.filters)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}
