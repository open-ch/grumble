package parse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrypeFile(t *testing.T) {
	var tests = []struct {
		name           string
		inputFile      string
		expectedOutput string
		expectedError  bool
	}{
		{
			name:      "Pretty print json content",
			inputFile: "test-data/grype_empty_structs.json",
			expectedOutput: `{
    "descriptor": {},
    "distro": {},
    "matches": {},
    "source": {}
}
`,
		},
		{
			name:          "Fails on invalid json",
			inputFile:     "test-data/grype_invalid_json.json",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outputJSON, err := GrypeFile(tc.inputFile)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, outputJSON)
			}
		})
	}
}

func TestGrypeReport(t *testing.T) {
	var tests = []struct {
		name           string
		input          string
		expectedOutput string
		expectedError  bool
	}{
		{
			name:  "Pretty print json content",
			input: `{"descriptor": {}, "distro": {}, "matches": {}, "source": {}}`,
			expectedOutput: `{
    "descriptor": {},
    "distro": {},
    "matches": {},
    "source": {}
}`,
		},
		{
			name:          "Fails on invalid json",
			input:         "(>O_O)>",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outputJSON, err := GrypeReport([]byte(tc.input))

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, outputJSON)
			}
		})
	}
}
