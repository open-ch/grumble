package scorecard

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/log"
)

// Entry is a single cached Scorecard result for one package, keyed by purl
// in Cache.Entries.
type Entry struct {
	Purl         string             `json:"purl"`
	License      string             `json:"license"`
	Probes       map[string]Outcome `json:"probes,omitempty"`
	RepoResolved bool               `json:"repoResolved"`
	FetchedAtS   int64              `json:"fetchedAtS"`
}

// Cache is the on-disk (Artifactory-backed) JSON cache of Scorecard results,
// keyed by purl.
type Cache struct {
	Entries map[string]Entry `json:"entries"`
}

// LoadCache reads a Cache from path. A missing or corrupt file results in an
// empty, usable Cache (zero value is valid) and a logged warning rather than
// an error, so a first run or a transient Artifactory issue never blocks
// enrichment.
func LoadCache(path string) *Cache {
	// nosemgrep: go-use-root-open-osag
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("scorecard: could not read cache file, starting empty", "path", path, "err", err)
		}
		return &Cache{Entries: map[string]Entry{}}
	}

	var c Cache
	if err := json.Unmarshal(b, &c); err != nil {
		log.Warn("scorecard: cache file is corrupt, starting empty", "path", path, "err", err)
		return &Cache{Entries: map[string]Entry{}}
	}
	if c.Entries == nil {
		c.Entries = map[string]Entry{}
	}
	return &c
}

// Get returns the cached entry for purl if present and not older than
// ttlDays.
func (c *Cache) Get(purl string, ttlDays int) (Entry, bool) {
	entry, ok := c.Entries[purl]
	if !ok {
		return Entry{}, false
	}

	age := time.Since(time.Unix(entry.FetchedAtS, 0))
	if age > time.Duration(ttlDays)*24*time.Hour {
		return Entry{}, false
	}
	return entry, true
}

// Put stores/overwrites the entry for entry.Purl.
func (c *Cache) Put(entry Entry) {
	if c.Entries == nil {
		c.Entries = map[string]Entry{}
	}
	c.Entries[entry.Purl] = entry
}

// Save writes the cache as JSON to path.
func (c *Cache) Save(path string) error {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal scorecard cache: %w", err)
	}
	// nosemgrep: go-use-root-open-osag
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write scorecard cache %s: %w", path, err)
	}
	return nil
}
