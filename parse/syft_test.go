package parse

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-ch/grumble/syft"

	"github.com/stretchr/testify/assert"
)

// create an empty &syft.Document object with all the properties filled
// in with bogus data from syft_empty.json. Compare the datastructure read against an expected document
func emptySyftDocument() *syft.Document {
	return &syft.Document{
		Schema: syft.Schema{Version: "13.0.0", URL: "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-13.0.0.json"},
		Source: syft.Source{
			ID:       "34d40fdc6ca13e9a3fa18415db216b50bff047716fae7d95a225c09732fe83fb",
			Name:     "user-image-input",
			Version:  "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368",
			Type:     "image",
			Metadata: map[string]any{"userInput": "user-image-input", "mediaType": "application/vnd.docker.distribution.manifest.v2+json"},
		},
		Distro: syft.LinuxRelease{
			PrettyName:       "debian",
			Name:             "debian",
			ID:               "debian",
			IDLike:           syft.IDLikes{"like!"},
			Version:          "1.2.3",
			VersionID:        "1.2.3",
			VersionCodename:  "",
			BuildID:          "",
			ImageID:          "",
			ImageVersion:     "",
			Variant:          "",
			VariantID:        "",
			HomeURL:          "",
			SupportURL:       "",
			BugReportURL:     "",
			PrivacyPolicyURL: "",
			CPEName:          "",
			SupportEnd:       "",
		},
		Descriptor: syft.Descriptor{
			Name:          "syft",
			Version:       "v0.42.0-bogus",
			Configuration: map[string]any{"config-key": "config-value"},
		},
		Artifacts:             []syft.Package{},
		ArtifactRelationships: []syft.Relationship{},
		Files:                 nil,
	}
}

func syftDocumentWithPackages() *syft.Document {
	syftDocument := emptySyftDocument()
	syftDocument.Artifacts = []syft.Package{
		{
			PackageBasicData: syft.PackageBasicData{
				ID:      "80210ebcba92e632",
				Name:    "package-1",
				Version: "1.0.1",
				Type:    "python",
				FoundBy: "the-cataloger-1",
				Locations: []syft.Location{{
					LocationData: syft.LocationData{
						Coordinates: syft.Coordinates{
							RealPath:     "/somefile-1.txt",
							FileSystemID: "sha256:100d5a55f9032faead28b7427fa3e650e4f0158f86ea89d06e1489df00cb8c6f"},
						AccessPath: "/somefile-1.txt"}}},
				Licenses: []syft.License{{Value: "MIT", SPDXExpression: "MIT", Type: "declared", URLs: []string{}, Locations: []syft.Location{}}},
				Language: "python",
				CPEs: []syft.CPE{
					{Value: "cpe:2.3:*:some:package:1:*:*:*:*:*:*:*"},
				},
				PURL: "a-purl-1",
			},
			PackageCustomData: syft.PackageCustomData{
				MetadataType: "python-package",
				Metadata:     map[string]any{"name": "package-1"},
			},
		},
		{
			PackageBasicData: syft.PackageBasicData{
				ID:      "4b756c6f6fb127a3",
				Name:    "package-2",
				Version: "2.0.1",
				Type:    "deb",
				FoundBy: "the-cataloger-2",
				Locations: []syft.Location{{
					LocationData: syft.LocationData{
						Coordinates: syft.Coordinates{
							RealPath:     "/somefile-2.txt",
							FileSystemID: "sha256:000fb9200890d3a19138478b20023023c0dce1c54352007c2863716780f049eb"},
						AccessPath: "/somefile-2.txt"}}},
				Licenses: []syft.License{},
				Language: "",
				CPEs: []syft.CPE{
					{Value: "cpe:2.3:*:some:package:2:*:*:*:*:*:*:*"},
				},
				PURL: "pkg:deb/debian/package-2@2.0.1",
			},
			PackageCustomData: syft.PackageCustomData{
				MetadataType: "dpkg-db-entry",
				Metadata:     map[string]any{"package": "package-2"},
			},
		},
	}
	return syftDocument
}

func TestSyftFile(t *testing.T) {
	var tests = []struct {
		name             string
		inputFile        string
		expectedDocument *syft.Document
		expectedError    bool
	}{
		{
			name:             "Read an empty syft document and compare against the target expected document",
			inputFile:        "testdata/syft/syft_empty.json",
			expectedDocument: emptySyftDocument(),
			expectedError:    false,
		},
		{
			name:             "Read a syft document with packages and compare against the target expected document",
			inputFile:        "testdata/syft/syft_packages.json",
			expectedDocument: syftDocumentWithPackages(),
			expectedError:    false,
		},
		{
			name:          "Fails on invalid json",
			inputFile:     "testdata/syft/syft_invalid_json.json",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sbom, err := SyftFile(tc.inputFile)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedDocument, sbom)
			}
		})
	}
}

func TestSyftSBOM(t *testing.T) {
	var tests = []struct {
		name           string
		input          string
		expectedOutput string
		expectedError  bool
	}{
		{
			name:           "Pretty print json content",
			input:          getTestReport(t, "testdata/syft/syft_empty.json"),
			expectedOutput: strings.TrimSpace(getTestReport(t, "testdata/syft/syft_empty.json")),
		},
		{
			name:          "Fails on invalid json",
			input:         "ლ(ಠ益ಠლ)",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report, err := SyftSBOM([]byte(tc.input))

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				outputJSON, err := json.MarshalIndent(report, jsonPrefix, jsonIndentSpacing)
				assert.NoError(t, err)
				assert.JSONEqf(t, tc.expectedOutput, string(outputJSON), "error message %s", "formatted")
			}
		})
	}
}
