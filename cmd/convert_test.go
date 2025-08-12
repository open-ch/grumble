package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-ch/grumble/grype"
)

func TestConvertGrypeToSARIF(t *testing.T) {
	tests := []struct {
		name        string
		setupInput  func(t *testing.T) string
		outputPath  string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful conversion with auto output path",
			setupInput: func(t *testing.T) string {
				return createTestGrypeFile(t, "test-grype.json")
			},
			outputPath: "",
			wantErr:    false,
		},
		{
			name: "successful conversion with custom output path",
			setupInput: func(t *testing.T) string {
				return createTestGrypeFile(t, "test-grype.json")
			},
			outputPath: "custom-output.sarif",
			wantErr:    false,
		},
		{
			name: "input file does not exist",
			setupInput: func(_ *testing.T) string {
				return "nonexistent-file.json"
			},
			outputPath:  "",
			wantErr:     true,
			errContains: "input file does not exist",
		},
		{
			name: "invalid grype json",
			setupInput: func(t *testing.T) string {
				return createInvalidGrypeFile(t, "invalid-grype.json")
			},
			outputPath:  "",
			wantErr:     true,
			errContains: "failed to parse grype file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// setup test directory
			tmpDir := t.TempDir()
			inputPath := filepath.Join(tmpDir, filepath.Base(tt.setupInput(t)))

			// copy test file to temp directory if it exists
			if _, err := os.Stat(tt.setupInput(t)); err == nil {
				content, err := os.ReadFile(tt.setupInput(t))
				assert.NoError(t, err)
				err = os.WriteFile(inputPath, content, 0644)
				assert.NoError(t, err)
			} else {
				inputPath = tt.setupInput(t) // use the path as-is for nonexistent files
			}

			outputPath := tt.outputPath
			if outputPath != "" {
				outputPath = filepath.Join(tmpDir, outputPath)
			}

			// run conversion
			err := convertGrypeToSARIF(inputPath, outputPath)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)

			// determine expected output path
			expectedOutput := outputPath
			if expectedOutput == "" {
				expectedOutput = inputPath[:len(inputPath)-len(filepath.Ext(inputPath))] + ".sarif"
			}

			// verify output file exists and is valid json
			assert.FileExists(t, expectedOutput)

			content, err := os.ReadFile(expectedOutput)
			assert.NoError(t, err)

			// verify it's valid json
			var sarifData map[string]any
			err = json.Unmarshal(content, &sarifData)
			assert.NoError(t, err)

			// verify it looks like a sarif report
			assert.Equal(t, "2.1.0", sarifData["version"])
			assert.Contains(t, sarifData, "runs")
		})
	}
}

func TestNewConvertCmd(t *testing.T) {
	cmd := getConvertCommand()

	assert.Equal(t, "convert", cmd.Use)
	assert.Contains(t, cmd.Short, "Convert a Grype JSON report to SARIF format")
	assert.NotEmpty(t, cmd.Long)
	assert.NotEmpty(t, cmd.Example)

	// verify assertd flags
	inputFlag := cmd.Flags().Lookup("input")
	assert.NotNil(t, inputFlag)
	assert.True(t, inputFlag.Value.String() == "")

	outputFlag := cmd.Flags().Lookup("output")
	assert.NotNil(t, outputFlag)
	assert.True(t, outputFlag.Value.String() == "")
}

// createTestGrypeFile creates a valid grype json file for testing
func createTestGrypeFile(t *testing.T, filename string) string {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, filename)

	grypeDoc := &grype.Document{
		Descriptor: grype.Descriptor{
			Version: "0.70.0",
		},
		Distro: grype.Distro{
			Name:    "ubuntu",
			Version: "20.04",
		},
		Matches: []*grype.Match{
			{
				Artifact: grype.Artifact{
					Name:     "libssl1.1",
					Version:  "1.1.1f-1ubuntu2",
					Type:     "deb",
					Language: "",
					Purl:     "pkg:deb/ubuntu/libssl1.1@1.1.1f-1ubuntu2",
					CPEs:     []string{"cpe:2.3:a:openssl:openssl:1.1.1f:*:*:*:*:*:*:*"},
					Locations: []grype.Location{
						{Path: "/var/lib/dpkg/status"},
					},
				},
				Vulnerability: grype.Vulnerability{
					ID:          "CVE-2023-1234",
					Description: "Test vulnerability",
					Severity:    "high",
					DataSource:  "ubuntu-security-notices",
					Namespace:   "ubuntu:20.04",
					Urls:        []string{"https://ubuntu.com/security/CVE-2023-1234"},
					CVSS: []grype.CVSS{
						{
							Version: "3.1",
							Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							Metrics: grype.Metrics{
								BaseScore:           7.5,
								ExploitabilityScore: 3.9,
								ImpactScore:         5.9,
							},
						},
					},
					Fix: grype.Fix{
						State:    "fixed",
						Versions: []string{"1.1.1f-1ubuntu2.17"},
					},
				},
			},
		},
		IgnoredMatches: []*grype.Match{},
		Source: grype.Source{
			Type:   "image",
			Target: "ubuntu:20.04",
		},
	}

	content, err := json.MarshalIndent(grypeDoc, "", "  ")
	assert.NoError(t, err)

	err = os.WriteFile(filePath, content, 0644)
	assert.NoError(t, err)

	return filePath
}

// createInvalidGrypeFile creates an invalid json file for testing error cases
func createInvalidGrypeFile(t *testing.T, filename string) string {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, filename)

	invalidJSON := `{"invalid": "json", "missing": "closing brace"`

	err := os.WriteFile(filePath, []byte(invalidJSON), 0644)
	assert.NoError(t, err)

	return filePath
}
