package scorecard

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseProbeReport(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantRepo    string
		wantOutcome map[string]Outcome
		wantErr     bool
	}{
		{
			name:     "parses a real scorecard --format=probe fixture",
			input:    readFixture(t, "testdata/probe-report.json"),
			wantRepo: "github.com/ossf/scorecard",
			wantOutcome: map[string]Outcome{
				"archived":                     OutcomeFalse,
				"notArchived":                  OutcomeTrue,
				"hasRecentCommits":             OutcomeTrue,
				"issueActivityByProjectMember": OutcomeNotApplicable,
				"hasLicenseFile":               OutcomeTrue,
				"hasFSFOrOSIApprovedLicense":   OutcomeTrue,
				"hasOSIApprovedLicense":        OutcomeError,
			},
		},
		{
			name:    "invalid json returns an error",
			input:   []byte(`{not-json`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseProbeReport(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantRepo, report.Repo)
			require.Equal(t, tt.wantOutcome, report.Probes())
		})
	}
}

func TestOutcomeIsNeutral(t *testing.T) {
	tests := []struct {
		name    string
		outcome Outcome
		want    bool
	}{
		{"True is not neutral", OutcomeTrue, false},
		{"False is not neutral", OutcomeFalse, false},
		{"NotApplicable is neutral", OutcomeNotApplicable, true},
		{"Error is neutral", OutcomeError, true},
		{"NotAvailable is neutral", OutcomeNotAvailable, true},
		{"NotSupported is neutral", OutcomeNotSupported, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.outcome.IsNeutral())
		})
	}
}

// TestExpectedProbesCoverage is the version-compat guard: every probe present
// in the recorded real-world fixture must be part of the pinned ExpectedProbes
// set. If Scorecard renames/removes a probe on upgrade, this fails loudly
// instead of silently dropping data.
func TestExpectedProbesCoverage(t *testing.T) {
	report, err := ParseProbeReport(readFixture(t, "testdata/probe-report.json"))
	require.NoError(t, err)

	expected := make(map[string]bool, len(ExpectedProbes))
	for _, p := range ExpectedProbes {
		expected[p] = true
	}

	for probe := range report.Probes() {
		require.Truef(t, expected[probe], "probe %q from fixture is not in ExpectedProbes; Scorecard CLI may have changed", probe)
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	// nosemgrep: go-use-root-open-osag
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}
