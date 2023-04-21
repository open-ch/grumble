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
			expectedOutput: readTestFile(t, "test-data/empty_grype.json"),
			format:         "json",
		},
		{
			name:           "Pretty: Prints unicorns for matches",
			document:       readTestGrype(t, "test-data/two_grypes.json"),
			expectedOutput: readTestFile(t, "test-data/two_pretty_grypes"),
			ignoreSpacing:  true,
			format:         "pretty",
		},
		{
			name:           "Pretty: Prints little for no matches",
			document:       &grype.Document{},
			expectedOutput: readTestFile(t, "test-data/pretty_empty_grype"),
			format:         "pretty",
		},
		{
			name:          "Fails on invalid format",
			expectedError: true,
			format:        "yamlyml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "test-data/CODEOWNERS")
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
