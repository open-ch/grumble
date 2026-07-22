package scorecard

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var errReadFailed = errors.New("boom")

func TestCLIReportLoaderLoad(t *testing.T) {
	fixture := readFixture(t, "testdata/probe-report.json")

	tests := []struct {
		name     string
		readFile func(path string) ([]byte, error)
		wantErr  string
		wantRepo string
	}{
		{
			name: "loads and validates a pre-generated probe report",
			readFile: func(path string) ([]byte, error) {
				require.Equal(t, "/tmp/scorecard-output.json", path)
				return fixture, nil
			},
			wantRepo: "github.com/ossf/scorecard",
		},
		{
			name: "read failure is wrapped",
			readFile: func(path string) ([]byte, error) {
				return nil, errReadFailed
			},
			wantErr: "read scorecard cli output",
		},
		{
			name: "invalid json is rejected",
			readFile: func(path string) ([]byte, error) {
				return []byte(`{not-json`), nil
			},
			wantErr: "parse scorecard probe report",
		},
		{
			name: "probes outside ExpectedProbes are rejected",
			readFile: func(path string) ([]byte, error) {
				return []byte(`{"repo":{"name":"github.com/ossf/scorecard"},"findings":[{"probe":"totallyNewProbe","outcome":"True"}]}`), nil
			},
			wantErr: "unexpected probe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := &CLIReportLoader{ReadFile: tt.readFile}

			report, err := loader.Load("/tmp/scorecard-output.json")

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantRepo, report.Repo)
		})
	}
}

func TestCLIReportLoaderLoadReader(t *testing.T) {
	fixture := readFixture(t, "testdata/probe-report.json")
	loader := &CLIReportLoader{}

	report, err := loader.LoadReader(bytes.NewReader(fixture))

	require.NoError(t, err)
	require.Equal(t, "github.com/ossf/scorecard", report.Repo)
}

func TestProbesFlag(t *testing.T) {
	require.Equal(t, "archived,notArchived,hasRecentCommits,issueActivityByProjectMember,"+
		"hasLicenseFile,hasFSFOrOSIApprovedLicense,hasOSIApprovedLicense", ProbesFlag())
}
