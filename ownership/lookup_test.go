package ownership

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFromCODEOWNERS(t *testing.T) {
	var tests = []struct {
		name           string
		codeownersPath string
		expectedError  bool
	}{
		{
			name:           "valid codeowner loads",
			codeownersPath: "testdata/CODEOWNERS",
		},
		{
			name:           "invalid codeowner fails",
			codeownersPath: "testdata/invalidCODEOWNERS",
			expectedError:  true,
		},
		{
			name:           "non existent file fails",
			codeownersPath: "testdata/nonExistentCODEOWNERS",
			expectedError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFromCODEOWNERS(tc.codeownersPath)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLookupFor(t *testing.T) {
	var tests = []struct {
		name           string
		path           string
		expectedOwners string
	}{
		{
			name:           "default owner for random path",
			path:           "random/README.md",
			expectedOwners: "@org-name/default-team",
		},
		{
			name:           "parent owner for sub path",
			path:           "example/path2/package.json",
			expectedOwners: "@org-name/example-team",
		},
		{
			name:           "nested path with different owner",
			path:           "example/other/package.json",
			expectedOwners: "@org-name/other-team",
		},
		{
			name:           "multiple owners for shared path",
			path:           "shared/package.json",
			expectedOwners: "@org-name/example-team,@org-name/other-team",
		},
		{
			name:           "parent owner for sub path with grype 0.64.0 bogus absolute path",
			path:           "/example/path2/package.json",
			expectedOwners: "@org-name/example-team",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, err := LoadFromCODEOWNERS("testdata/CODEOWNERS")
			assert.NoError(t, err)
			SetLookup(l)

			owners, err := LookupFor(tc.path)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOwners, strings.Join(owners, ","))
		})
	}
}

func TestIsOwnedBy(t *testing.T) {
	var tests = []struct {
		name        string
		owners      []string
		path        string
		expectOwned bool
	}{
		{
			name:        "path owned by single owners",
			owners:      []string{"@org-name/example-team"},
			path:        "example/README.md",
			expectOwned: true,
		},
		{
			name:        "absolut path owned by single owners (BE-763)",
			owners:      []string{"@org-name/example-team"},
			path:        "/example/README.md",
			expectOwned: true,
		},
		{
			name:        "path owned by one of seveal owners",
			owners:      []string{"@org-name/default-team", "@org-name/other-team", "@org-name/example-team"},
			path:        "example/README.md",
			expectOwned: true,
		},
		{
			name:        "path with multiple owners owned by one of seveal owners",
			owners:      []string{"@org-name/default-team", "@org-name/other-team", "@org-name/example-team"},
			path:        "shared/README.md",
			expectOwned: true,
		},
		{
			name:   "path not owned by any of seveal owners",
			owners: []string{"@org-name/invalid-team", "@org-name/other-team", "@org-name/example-team"},
			path:   "random/README.md",
		},
		{
			name:   "path not owned by single owner",
			owners: []string{"@org-name/example-team"},
			path:   "random/README.md",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, err := LoadFromCODEOWNERS("testdata/CODEOWNERS")
			assert.NoError(t, err)
			SetLookup(l)

			isOwned, err := IsOwnedBy(tc.path, tc.owners)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectOwned, isOwned)
		})
	}
}
