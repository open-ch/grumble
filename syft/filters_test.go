package syft

import (
	"github.com/open-ch/grumble/filters"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var testArtifacts = map[string]*Package{
	"example/path1": {
		PackageBasicData: PackageBasicData{
			Name: "package1",
			Locations: locations{
				{
					LocationData: LocationData{AccessPath: "example/path1"},
				},
			},
		},
	},
	"example/path2": {
		PackageBasicData: PackageBasicData{
			Name: "package2",
			Locations: locations{
				{
					LocationData: LocationData{AccessPath: "example/path2"},
				},
			},
		},
	},
	"example/multiple": {
		PackageBasicData: PackageBasicData{
			Name: "package3",
			Locations: locations{
				{
					LocationData: LocationData{AccessPath: "example/path1"},
				},
				{
					LocationData: LocationData{AccessPath: "example/path2"},
				},
			},
		},
	},
	"example/long": {
		PackageBasicData: PackageBasicData{
			Name: "package4",
			Locations: locations{
				{
					LocationData: LocationData{AccessPath: "example/path1/very/long/package/location"},
				},
			},
		},
	},
	"other/long": {
		PackageBasicData: PackageBasicData{
			Name: "package5",
			Locations: locations{
				{
					LocationData: LocationData{AccessPath: "other/path1/very/long/package/location"},
				},
			},
		},
	},
}

var testFiles = map[string]*File{
	"example/path1": {
		Location: Coordinates{RealPath: "example/path1"},
	},
	"example/path2": {
		Location: Coordinates{RealPath: "example/path2"},
	},
	"example/long": {
		Location: Coordinates{RealPath: "example/path1/very/long/package/location"},
	},
	"other/long": {
		Location: Coordinates{RealPath: "other/path1/very/long/package/location"},
	},
}

var testDocument = Document{
	Artifacts: []Package{
		*testArtifacts["example/path1"],
		*testArtifacts["example/path2"],
		*testArtifacts["example/multiple"],
	},
	Files: []File{
		*testFiles["example/path1"],
		*testFiles["example/path2"],
		*testFiles["example/long"],
		*testFiles["other/long"],
	},
}

func TestPath(t *testing.T) {
	var tests = []struct {
		name              string
		document          *Document
		expectedArtifacts []Package
		expectedFiles     []File
		filters           filters.Filters
	}{
		{
			name:              "Empty filters return empty packages",
			document:          &Document{},
			expectedArtifacts: make([]Package, 0),
			expectedFiles:     make([]File, 0),
		},
		{
			name:              "Empty filters return all matches in document",
			document:          &testDocument,
			expectedArtifacts: testDocument.Artifacts,
			expectedFiles:     testDocument.Files,
		},
		{
			name:              "Severity not supported for syft, return empty",
			document:          &testDocument,
			filters:           filters.Filters{Severity: "Medium"},
			expectedArtifacts: make([]Package, 0),
			expectedFiles:     make([]File, 0),
		},
		{
			name:              "Fix State not supported for syft, return empty",
			document:          &testDocument,
			filters:           filters.Filters{FixState: "fixed"},
			expectedArtifacts: make([]Package, 0),
			expectedFiles:     make([]File, 0),
		},
		{
			name:              "Wrong path returns nothing",
			document:          &testDocument,
			filters:           filters.Filters{PathPrefix: "wrong/,another/"},
			expectedArtifacts: make([]Package, 0),
			expectedFiles:     make([]File, 0),
		},
		{
			name:     "Correct path returns package 1 and package 3",
			document: &testDocument,
			filters:  filters.Filters{PathPrefix: "example/path1"},
			expectedArtifacts: []Package{
				*testArtifacts["example/path1"],
				*testArtifacts["example/multiple"],
			},
			expectedFiles: []File{
				*testFiles["example/path1"],
				*testFiles["example/long"],
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filteredDoc := tc.document.Filter(&tc.filters)

			assert.Equal(t, tc.expectedArtifacts, filteredDoc.Artifacts)
			assert.Equal(t, tc.expectedFiles, filteredDoc.Files)
		})
	}
}

func TestCodeowners(t *testing.T) {
	var tests = []struct {
		name              string
		document          *Document
		filters           filters.Filters
		expectedArtifacts []Package
		expectedFiles     []File
	}{
		{
			name:              "Empty filters return empty packages",
			document:          &Document{},
			expectedArtifacts: make([]Package, 0),
			expectedFiles:     make([]File, 0),
		},
		{
			name:              "Matches single owner",
			document:          &testDocument,
			filters:           filters.Filters{Codeowners: "@org-name/example-team"},
			expectedArtifacts: testDocument.Artifacts,
			expectedFiles:     testDocument.Files,
		},
		{
			name: "Matches one of several owners",
			document: &Document{
				Artifacts: []Package{
					*testArtifacts["example/path1"],
					*testArtifacts["example/path2"],
					*testArtifacts["example/multiple"],
					*testArtifacts["other/long"],
				},
				Files: []File{
					*testFiles["example/path1"],
					*testFiles["example/path2"],
					*testFiles["example/long"],
					*testFiles["other/long"],
				},
			},
			filters:           filters.Filters{Codeowners: "@org-name/non-existent-team,@org-name/other-team"},
			expectedArtifacts: []Package{*testArtifacts["other/long"]},
			expectedFiles:     []File{*testFiles["other/long"]},
		},
		{
			name:              "Mismatch non owner teams",
			document:          &testDocument,
			filters:           filters.Filters{Codeowners: "@org-name/other-team"},
			expectedArtifacts: make([]Package, 0),
			expectedFiles:     make([]File, 0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("codeownersPath", "testdata/CODEOWNERS")
			filteredDoc := tc.document.Filter(&tc.filters)

			assert.Equal(t, tc.expectedArtifacts, filteredDoc.Artifacts)
		})
	}
}
