package syft

import (
	"sort"
)

// Sort returns a new shallow copy of a document with the packages sorted
// by multiple keys as follows:
// - id
// - name
// - version
// - path
func (d *Document) Sort() *Document {
	sd := &Document{
		Descriptor:            d.Descriptor,
		Distro:                d.Distro,
		Source:                d.Source,
		Schema:                d.Schema,
		ArtifactRelationships: d.ArtifactRelationships,
		Files:                 d.Files,
	}
	sd.Artifacts = append(sd.Artifacts, d.Artifacts...)

	sort.Slice(sd.Artifacts, func(i, j int) bool {
		return compareMatches(&sd.Artifacts[i], &sd.Artifacts[j])
	})

	return sd
}

// compareMatches is a sort helper it compares 2 artifacts
// and returns true if j is smaller than i.
// The goal is to sort over multiple keys:
// Id first (string)
// Name (string)
// Then version (string)
// Finally the path
func compareMatches(i, j *Package) bool {
	if i.ID != j.ID {
		return i.ID > j.ID
	}

	if i.Name != j.Name {
		return i.Name > j.Name
	}

	if i.Version != j.Version {
		return i.Version > j.Version
	}

	return i.PURL > j.PURL
}
