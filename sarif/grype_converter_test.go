package sarif

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-ch/grumble/grype"
)

func TestGrypeToSARIF(t *testing.T) {
	tests := []struct {
		name        string
		grypeDoc    *grype.Document
		wantErr     bool
		wantRules   int
		wantResults int
	}{
		{
			name:     "nil document",
			grypeDoc: nil,
			wantErr:  true,
		},
		{
			name: "empty document",
			grypeDoc: &grype.Document{
				Descriptor: grype.Descriptor{
					Version: "0.70.0",
				},
				Matches:        []*grype.Match{},
				IgnoredMatches: []*grype.Match{},
			},
			wantErr:     false,
			wantRules:   0,
			wantResults: 0,
		},
		{
			name:        "document with matches",
			grypeDoc:    createTestGrypeDocument(),
			wantErr:     false,
			wantRules:   3, // Three unique vulnerabilities: CVE-2023-1234, CVE-2023-5678, CVE-2023-9012
			wantResults: 3, // Two matches + one ignored
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GrypeToSARIF(tt.grypeDoc)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Len(t, result.Runs, 1)

			run := result.Runs[0]
			assert.Equal(t, "grype", run.Tool.Driver.Name)
			assert.Len(t, run.Tool.Driver.Rules, tt.wantRules)
			assert.Len(t, run.Results, tt.wantResults)
		})
	}
}

func TestConvertMatchToResult(t *testing.T) {
	tests := []struct {
		name      string
		match     *grype.Match
		wantErr   bool
		wantLevel string
	}{
		{
			name:    "nil match",
			match:   nil,
			wantErr: true,
		},
		{
			name:      "critical vulnerability",
			match:     createTestMatch("CVE-2023-1234", "critical"),
			wantErr:   false,
			wantLevel: "error",
		},
		{
			name:      "medium vulnerability",
			match:     createTestMatch("CVE-2023-5678", "medium"),
			wantErr:   false,
			wantLevel: "warning",
		},
		{
			name:      "low vulnerability",
			match:     createTestMatch("CVE-2023-9012", "low"),
			wantErr:   false,
			wantLevel: "note",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertMatchToResult(tt.match)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.wantLevel, *result.Level)
			assert.NotNil(t, result.Message)
			assert.Greater(t, len(result.Locations), 0)
		})
	}
}

func TestConvertSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"negligible", "note"},
		{"unknown", "warning"},
		{"", "warning"},
		{"CRITICAL", "error"}, // Test case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := convertSeverityToLevel(tt.severity)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCreateRuleFromVulnerability(t *testing.T) {
	vuln := &grype.Vulnerability{
		ID:          "CVE-2023-1234",
		Description: "Test vulnerability description",
		Severity:    "high",
		DataSource:  "nvd",
		Namespace:   "nvd:cpe",
		Urls:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-1234"},
		CVSS: []grype.CVSS{
			{
				Version: "3.1",
				Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Metrics: grype.Metrics{
					BaseScore:           9.8,
					ExploitabilityScore: 3.9,
					ImpactScore:         5.9,
				},
			},
		},
	}

	rule := createRuleFromVulnerability(vuln)

	assert.Equal(t, "CVE-2023-1234", rule.ID)
	assert.Equal(t, "Test vulnerability description", *rule.FullDescription.Text)
	assert.Equal(t, "error", rule.DefaultConfiguration.Level)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2023-1234", *rule.HelpURI)
	assert.NotNil(t, rule.Properties)

	// Check properties - accessing the map directly since Properties is not a pointer
	assert.Equal(t, "high", rule.Properties["severity"])
	assert.Equal(t, "nvd", rule.Properties["dataSource"])
	assert.Equal(t, 9.8, rule.Properties["cvssScore"])
}

func TestSARIFOutputStructure(t *testing.T) {
	grypeDoc := createTestGrypeDocument()
	sarifReport, err := GrypeToSARIF(grypeDoc)
	assert.NoError(t, err)

	// Convert to JSON to verify structure
	jsonData, err := json.MarshalIndent(sarifReport, "", "  ")
	assert.NoError(t, err)

	// Verify it's valid JSON
	var parsed map[string]any
	err = json.Unmarshal(jsonData, &parsed)
	assert.NoError(t, err)

	// Check assertd SARIF fields
	assert.Equal(t, "2.1.0", parsed["version"])
	assert.Contains(t, parsed, "runs")

	runs, ok := parsed["runs"].([]any)
	assert.True(t, ok, "run should be a []any")
	assert.Len(t, runs, 1)

	run, ok := runs[0].(map[string]any)
	assert.True(t, ok, "run should be a map[string]any")
	assert.Contains(t, run, "tool")
	assert.Contains(t, run, "results")
}

// Helper functions for creating test data

func createTestGrypeDocument() *grype.Document {
	return &grype.Document{
		Descriptor: grype.Descriptor{
			Version: "0.70.0",
		},
		Distro: grype.Distro{
			Name:    "ubuntu",
			Version: "20.04",
		},
		Matches: []*grype.Match{
			createTestMatch("CVE-2023-1234", "critical"),
			createTestMatch("CVE-2023-5678", "medium"),
		},
		IgnoredMatches: []*grype.Match{
			createTestMatchWithIgnoreRule("CVE-2023-9012", "low"),
		},
		Source: grype.Source{
			Type:   "image",
			Target: "ubuntu:20.04",
		},
	}
}

func createTestMatch(vulnID, severity string) *grype.Match {
	return &grype.Match{
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
			ID:          vulnID,
			Description: "Test vulnerability for " + vulnID,
			Severity:    severity,
			DataSource:  "ubuntu-security-notices",
			Namespace:   "ubuntu:20.04",
			Urls:        []string{"https://ubuntu.com/security/" + vulnID},
			CVSS: []grype.CVSS{
				{
					Version: "3.1",
					Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Metrics: grype.Metrics{
						BaseScore:           getSeverityScore(severity),
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
		MatchDetails: []grype.MatchDetail{
			{
				Type:    "exact-direct-match",
				Matcher: "dpkg-matcher",
				SearchedBy: grype.SearchedBy{
					Namespace: "ubuntu:20.04",
				},
				Found: grype.Found{
					VersionConstraint: "< 1.1.1f-1ubuntu2.17",
					VulnerabilityID:   vulnID,
				},
			},
		},
	}
}

func createTestMatchWithIgnoreRule(vulnID, severity string) *grype.Match {
	match := createTestMatch(vulnID, severity)
	match.AppliedIgnoreRules = []grype.IgnoreRule{
		{
			Vulnerability: vulnID,
		},
	}
	return match
}

func getSeverityScore(severity string) float64 {
	switch severity {
	case "critical":
		return 9.8
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 0.0
	}
}
