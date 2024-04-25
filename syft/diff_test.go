package syft

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testPackage = Package{
	PackageBasicData: PackageBasicData{
		ID:      "a59e0bf496035f00",
		Name:    "example",
		Version: "v1.0.0",
		Type:    "golang",
		FoundBy: "golang",
		Locations: []Location{{
			LocationData: LocationData{
				AccessPath: "example/path1/relevantFile",
			},
		}},
		PURL:     "pkg:golang/example.com/example@v1.0.0",
		Licenses: []License{},
		Language: "golang",
	},
}

var testPackage2 = Package{
	PackageBasicData: PackageBasicData{
		ID:      "a59e0bf496035f03",
		Name:    "example2",
		Version: "v1.0.0",
		Type:    "golang",
		FoundBy: "golang",
		Locations: []Location{{
			LocationData: LocationData{
				AccessPath: "example/path1/relevantFile2",
			},
		}},
		PURL:     "pkg:golang/example.com/example2@v1.0.0",
		Licenses: []License{},
		Language: "golang",
	},
}

var testPackage3 = Package{
	PackageBasicData: PackageBasicData{
		ID:      "a59e0bf496035f04",
		Name:    "example3",
		Version: "v1.0.0",
		Type:    "golang",
		FoundBy: "golang",
		Locations: []Location{{
			LocationData: LocationData{
				AccessPath: "example/path1/relevantFile3",
			},
		}},
		PURL:     "pkg:golang/example.com/example3@v1.0.0",
		Licenses: []License{},
		Language: "golang",
	},
}

var testRelationshipWithFile = Relationship{
	Parent: "a59e0bf496035f00",
	Child:  "a59e0bf496035f01",
	Type:   "evident-by",
}

var testRelationshipWithFile2 = Relationship{
	Parent: "a59e0bf496035f03",
	Child:  "a59e0bf496035f01",
	Type:   "evident-by",
}

var testRelationshipWithoutFile = Relationship{
	Parent: "a59e0bf496035f03",
	Child:  "a59e0bf496035f04",
	Type:   "evident-by",
}

var testFile = File{
	ID: "a59e0bf496035f01",
	Location: Coordinates{
		RealPath: "example/path1/relevantFile",
	},
}

func TestDiff(t *testing.T) {
	var tests = []struct {
		name            string
		before          *Document
		after           *Document
		expectedAdded   *Document
		expectedRemoved *Document
	}{
		{
			name:            "Empty documents have no differences",
			before:          &Document{},
			after:           &Document{},
			expectedAdded:   &Document{Files: []File{}, Artifacts: []Package{}, ArtifactRelationships: []Relationship{}},
			expectedRemoved: &Document{Files: []File{}, Artifacts: []Package{}, ArtifactRelationships: []Relationship{}},
		},
		{
			name:            "Detect package after it was added",
			before:          &Document{},
			after:           &Document{Artifacts: []Package{testPackage}},
			expectedAdded:   &Document{Files: []File{}, Artifacts: []Package{testPackage}, ArtifactRelationships: []Relationship{}},
			expectedRemoved: &Document{Files: []File{}, Artifacts: []Package{}, ArtifactRelationships: []Relationship{}},
		},
		{
			name:            "Detect package after it was removed",
			before:          &Document{Artifacts: []Package{testPackage}},
			after:           &Document{},
			expectedAdded:   &Document{Files: []File{}, Artifacts: []Package{}, ArtifactRelationships: []Relationship{}},
			expectedRemoved: &Document{Files: []File{}, Artifacts: []Package{testPackage}, ArtifactRelationships: []Relationship{}},
		},
		{
			name:            "Keeps relationships and relevant files for added packages",
			before:          &Document{},
			after:           &Document{Artifacts: []Package{testPackage}, ArtifactRelationships: []Relationship{testRelationshipWithFile}, Files: []File{testFile}},
			expectedAdded:   &Document{Files: []File{testFile}, Artifacts: []Package{testPackage}, ArtifactRelationships: []Relationship{testRelationshipWithFile}},
			expectedRemoved: &Document{Files: []File{}, Artifacts: []Package{}, ArtifactRelationships: []Relationship{}},
		},
		{
			name:            "Avoids duplicate files for added packages",
			before:          &Document{},
			after:           &Document{Artifacts: []Package{testPackage, testPackage2}, ArtifactRelationships: []Relationship{testRelationshipWithFile, testRelationshipWithFile2}, Files: []File{testFile}},
			expectedAdded:   &Document{Files: []File{testFile}, Artifacts: []Package{testPackage2, testPackage}, ArtifactRelationships: []Relationship{testRelationshipWithFile, testRelationshipWithFile2}},
			expectedRemoved: &Document{Files: []File{}, Artifacts: []Package{}, ArtifactRelationships: []Relationship{}},
		},
		{
			name:            "Correctly recognizes added and removed packages at the same time",
			before:          &Document{Artifacts: []Package{testPackage}, ArtifactRelationships: []Relationship{testRelationshipWithFile}, Files: []File{testFile}},
			after:           &Document{Artifacts: []Package{testPackage2, testPackage3}, ArtifactRelationships: []Relationship{testRelationshipWithoutFile}, Files: []File{}},
			expectedAdded:   &Document{Files: []File{}, Artifacts: []Package{testPackage3, testPackage2}, ArtifactRelationships: []Relationship{testRelationshipWithoutFile}},
			expectedRemoved: &Document{Files: []File{testFile}, Artifacts: []Package{testPackage}, ArtifactRelationships: []Relationship{testRelationshipWithFile}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			added, removed := Diff(tc.before, tc.after)

			assert.Equal(t, tc.expectedAdded, added)
			assert.Equal(t, tc.expectedRemoved, removed)
		})
	}
}
