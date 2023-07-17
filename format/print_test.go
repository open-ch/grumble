package format

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/parse"
)

func TestPrint(t *testing.T) {
	var tests = []struct {
		name           string
		document       *grype.Document
		ignoreSpacing  bool
		expectedOutput string
		expectedError  bool
		format         string
	}{
		{
			name:           "JSON: Nil is null",
			expectedOutput: "null\n",
			format:         "json",
		},
		{
			name:           "JSON: Serializes valid document",
			document:       &grype.Document{},
			expectedOutput: readTestFile(t, "testdata/empty_grype.json"),
			format:         "json",
		},
		{
			name:           "Pretty: Prints results with a few details and summary",
			document:       readTestGrype(t, "testdata/two_grypes.json"),
			expectedOutput: readTestFile(t, "testdata/two_pretty_grypes"),
			ignoreSpacing:  true,
			format:         "pretty",
		},
		{
			name:           "Pretty: Prints little for no matches",
			document:       &grype.Document{},
			expectedOutput: readTestFile(t, "testdata/pretty_empty_grype"),
			format:         "pretty",
		},
		{
			name:           "Prometheus: Prints header and metrics",
			document:       readTestGrype(t, "testdata/two_grypes.json"),
			expectedOutput: readTestFile(t, "testdata/two_prometheus_grypes"),
			format:         "prometheus",
		},
		{
			name:           "Prometheus: Prints only header for no matches",
			document:       &grype.Document{},
			expectedOutput: "# TYPE test_vulnerability gauge\n",
			format:         "prometheus",
		},
		{
			name:           "Prometheus: Prints header and metrics no duplicates",
			document:       readTestGrype(t, "testdata/two_grypes_duplicates.json"),
			expectedOutput: readTestFile(t, "testdata/two_prometheus_grypes"),
			format:         "prometheus",
		},
		{
			name:           "Short: Prints little for no matches",
			document:       &grype.Document{},
			expectedOutput: "No matches in document\n",
			format:         "short",
		},
		{
			name:           "Short: Prints results",
			document:       readTestGrype(t, "testdata/two_grypes.json"),
			expectedOutput: "Medium   pkg:npm/example@1.0.0 example/libs/examples/package-lock.json CVE-0000-0000\n",
			ignoreSpacing:  true,
			format:         "short",
		},
		{
			name:          "Fails on invalid format",
			expectedError: true,
			format:        "yamlyml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			viper.Set("prometheusMetricName", "test_vulnerability")
			var outputStrBuilder strings.Builder
			fmtr := NewFormatter(tc.format, &outputStrBuilder)
			err := fmtr.Print(tc.document)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				output := outputStrBuilder.String()
				if tc.ignoreSpacing {
					output = trimLines(output)
				}
				assert.Equal(t, tc.expectedOutput, output)
			}
		})
	}
}

func TestPrintDiff(t *testing.T) {
	var tests = []struct {
		name           string
		diff           *grype.DocumentDiff
		ignoreSpacing  bool
		expectedOutput string
		expectedError  bool
		format         string
	}{
		{
			name:           "JSON: Nil is null",
			expectedOutput: "null\n",
			format:         "json",
		},
		{
			name:           "JSON: Serializes valid document",
			diff:           &grype.DocumentDiff{},
			expectedOutput: readTestFile(t, "testdata/empty_diff.json"),
			format:         "json",
		},
		{
			name: "Prometheus: Prints only header no changes",
			diff: &grype.DocumentDiff{},
			expectedOutput: "# TYPE test_vulnerability_new_timestamp_seconds gauge\n" +
				"# TYPE test_vulnerability_removed_timestamp_seconds gauge\n",
			format: "prometheus",
		},
		{
			name: "Prometheus: Prints added items as new and removed as remvoed",
			diff: &grype.DocumentDiff{
				Added: []grype.Match{{
					Artifact: grype.Artifact{
						Locations: []grype.Location{
							{Path: "test"},
						},
					},
				}},
				Removed: []grype.Match{{
					Artifact: grype.Artifact{
						Locations: []grype.Location{
							{Path: "test"},
						},
					},
				}},
			},
			expectedOutput: "# TYPE test_vulnerability_new_timestamp_seconds gauge\n" +
				`test_vulnerability_new_timestamp_seconds{id="",severity="",artifact="",licenses="",path="test",codeowners="@org-name/default-team"} 1676329200` + "\n" +
				"# TYPE test_vulnerability_removed_timestamp_seconds gauge\n" +
				`test_vulnerability_removed_timestamp_seconds{id="",severity="",artifact="",licenses="",path="test",codeowners="@org-name/default-team"} 1676329200` + "\n",
			format: "prometheus",
		},
		{
			name:          "Fails on invalid format",
			expectedError: true,
			format:        "yamlyml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			viper.Set("prometheusMetricName", "test_vulnerability")
			viper.Set("now", "1676329200")
			var outputStrBuilder strings.Builder
			fmtr := NewFormatter(tc.format, &outputStrBuilder)
			err := fmtr.PrintDiff(tc.diff)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				output := outputStrBuilder.String()
				if tc.ignoreSpacing {
					output = trimLines(output)
				}
				assert.Equal(t, tc.expectedOutput, output)
			}
		})
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	return string(content)
}

func readTestGrype(t *testing.T, path string) *grype.Document {
	t.Helper()
	grypeDoc, err := parse.GrypeFile(path)
	assert.NoError(t, err)
	return grypeDoc
}

// trimLines removes white space at the end of lines because when using
// Width() lipgloss might add lots of spaces when rendering.
func trimLines(render string) string {
	lines := strings.Split(render, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}
