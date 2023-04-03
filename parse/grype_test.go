package parse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGrype(t *testing.T) {
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

			outputJSON, err := ParseGrype(tc.inputFile)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, outputJSON)
			}
		})
	}
}
