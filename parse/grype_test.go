package parse

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
			name:           "Grype without matches reserialized to pretty printed json",
			inputFile:      "testdata/grype/grype_empty.json",
			expectedOutput: strings.TrimSpace(getTestReport(t, "testdata/grumble/grumble_grype_empty.json")),
		},
		{
			name:           "Grype matches are reserialized",
			inputFile:      "testdata/grype/grype_match.json",
			expectedOutput: strings.TrimSpace(getTestReport(t, "testdata/grumble/grumble_grype_match.json")),
		},
		{
			name:           "Grype ignored matches are reserialized",
			inputFile:      "testdata/grype/grype_ignored_match.json",
			expectedOutput: strings.TrimSpace(getTestReport(t, "testdata/grumble/grumble_grype_ignored_match.json")),
		},
		{
			name:          "Fails on invalid json",
			inputFile:     "testdata/grype/grype_invalid_json.json",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := GrypeFile(tc.inputFile)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				outputJSON, err := json.MarshalIndent(report, jsonPrefix, jsonIndentSpacing)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, string(outputJSON))
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
			name:           "Pretty print json content",
			input:          getTestReport(t, "testdata/grype/grype_empty.json"),
			expectedOutput: strings.TrimSpace(getTestReport(t, "testdata/grumble/grumble_grype_empty.json")),
		},
		{
			name:          "Fails on invalid json",
			input:         "(>O_O)>",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := GrypeReport([]byte(tc.input))

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				outputJSON, err := json.MarshalIndent(report, jsonPrefix, jsonIndentSpacing)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, string(outputJSON))
			}
		})
	}
}

func createTmpFolder(t *testing.T) string {
	t.Helper()
	testFolderPath, err := os.MkdirTemp("", "GrypeTest")
	assert.NoError(t, err)

	return testFolderPath
}

func TestWriteGrypeFile(t *testing.T) {
	t.Run("TestWriteGrypeFile", func(t *testing.T) {
		testFolder := createTmpFolder(t)
		defer os.RemoveAll(testFolder)

		// Read the source file
		grypeDocument, err := GrypeFile("testdata/grype/grype_match.json")
		assert.NoError(t, err)

		// Write the file
		err = WriteGrypeFile(grypeDocument, filepath.Join(testFolder, "grype-write-test.json"))
		assert.NoError(t, err)

		// Read the written file
		writtenGrypeDocument, err := GrypeFile(filepath.Join(testFolder, "grype-write-test.json"))
		assert.NoError(t, err)

		// Compare the file contents
		assert.Equal(t, grypeDocument, writtenGrypeDocument)
	})
}
