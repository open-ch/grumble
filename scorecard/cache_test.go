package scorecard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadCache(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		writeFile   bool
		wantEntries int
	}{
		{
			name:        "loads existing valid cache",
			fileContent: `{"entries":{"pkg:npm/lodash@4.17.21":{"purl":"pkg:npm/lodash@4.17.21","license":"MIT","repoResolved":true,"fetchedAtS":1000}}}`,
			writeFile:   true,
			wantEntries: 1,
		},
		{
			name:        "missing file returns empty cache",
			writeFile:   false,
			wantEntries: 0,
		},
		{
			name:        "corrupt file returns empty cache",
			fileContent: `{not-json`,
			writeFile:   true,
			wantEntries: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "cache.json")
			if tt.writeFile {
				require.NoError(t, os.WriteFile(path, []byte(tt.fileContent), 0o600))
			}

			c := LoadCache(path)
			require.NotNil(t, c)
			require.Len(t, c.Entries, tt.wantEntries)
		})
	}
}

func TestCacheGet(t *testing.T) {
	const ttlDays = 7
	now := time.Now()

	tests := []struct {
		name    string
		entries map[string]Entry
		purl    string
		wantOK  bool
	}{
		{
			name: "hit within ttl",
			entries: map[string]Entry{
				"pkg:npm/lodash@4.17.21": {Purl: "pkg:npm/lodash@4.17.21", FetchedAtS: now.Add(-1 * 24 * time.Hour).Unix()},
			},
			purl:   "pkg:npm/lodash@4.17.21",
			wantOK: true,
		},
		{
			name: "expired entry is a miss",
			entries: map[string]Entry{
				"pkg:npm/lodash@4.17.21": {Purl: "pkg:npm/lodash@4.17.21", FetchedAtS: now.Add(-30 * 24 * time.Hour).Unix()},
			},
			purl:   "pkg:npm/lodash@4.17.21",
			wantOK: false,
		},
		{
			name:    "unknown purl is a miss",
			entries: map[string]Entry{},
			purl:    "pkg:npm/lodash@4.17.21",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cache{Entries: tt.entries}
			entry, ok := c.Get(tt.purl, ttlDays)
			require.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.Equal(t, tt.purl, entry.Purl)
			}
		})
	}
}

func TestCachePutAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	c := &Cache{}
	c.Put(Entry{Purl: "pkg:npm/lodash@4.17.21", License: "MIT", RepoResolved: true, FetchedAtS: time.Now().Unix()})

	require.NoError(t, c.Save(path))

	reloaded := LoadCache(path)
	require.Len(t, reloaded.Entries, 1)
	entry, ok := reloaded.Entries["pkg:npm/lodash@4.17.21"]
	require.True(t, ok)
	require.Equal(t, "MIT", entry.License)
}
