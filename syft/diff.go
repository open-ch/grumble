package syft

func prepareDiff(d *Document) *Document {
	return &Document{
		Descriptor:            d.Descriptor,
		Distro:                d.Distro,
		Source:                d.Source,
		Schema:                d.Schema,
		Artifacts:             []Package{},
		ArtifactRelationships: []Relationship{},
		Files:                 []File{},
	}
}

// Diff takes 2 syft reports and returns the difference between them
// for introduced or removed dependencies.
//
//nolint:nonamedreturns // revive and golint disagree on this
func Diff(before, after *Document) (addedArtifacts, removedArtifacts *Document) {
	// Sort the packages in the documents
	oldDocument := before.Sort()
	newDocument := after.Sort()

	// Creates lookup tables to ease the documents comparisons
	oldPackages := buildPackageMatchKeyLookup(oldDocument)
	newPackages := buildPackageMatchKeyLookup(newDocument)

	added := createDifferenceFor(prepareDiff(after), newDocument, oldPackages)
	removed := createDifferenceFor(prepareDiff(after), oldDocument, newPackages)

	return added, removed
}

func createDifferenceFor(base *Document,
	inputDocument *Document,
	packages map[string]*Package,
) *Document {
	// Contains all the relationships in which a specific package is a parent
	parentRelationshipLookup := buildParentRelationshipLookup(inputDocument)
	// Contains all the relationships in which a specific package is a child
	childrenRelationshipLookup := buildChildrenRelationshipLookup(inputDocument)
	fileLookup := buildFileLookup(inputDocument)

	// Relationships and files are handled in a special way, since by adding a package this could be a direct dependency of another one
	diffRelationships := map[string]*Relationship{}
	diffFiles := map[string]*File{}

	for i := range inputDocument.Artifacts {
		uid := inputDocument.Artifacts[i].UniqueID()
		_, existsBefore := packages[uid]
		if !existsBefore {
			base.Artifacts = append(base.Artifacts, inputDocument.Artifacts[i])
			buildRelationshipsAndFiles(diffRelationships, inputDocument.Artifacts[i].ID, parentRelationshipLookup, diffFiles, fileLookup)
			buildRelationshipsAndFiles(diffRelationships, inputDocument.Artifacts[i].ID, childrenRelationshipLookup, diffFiles, fileLookup)
		}
	}
	base.ArtifactRelationships = mapToSliceRelationship(diffRelationships)
	base.Files = mapToSliceFile(diffFiles)

	return base
}

func buildRelationshipsAndFiles(diffRelationship map[string]*Relationship, artifactID string, relationshipLookup map[string]*[]Relationship, files, fileLookup map[string]*File) {
	if relationshipLookup[artifactID] != nil {
		relationships := *relationshipLookup[artifactID]
		for j := range relationships {
			if diffRelationship[relationships[j].UniqueID()] == nil {
				diffRelationship[relationships[j].UniqueID()] = &relationships[j]
			}
		}
		addFilesFromRelationships(files, relationships, fileLookup)
	}
}

func addFilesFromRelationships(fileList map[string]*File, relationships []Relationship, fileLookup map[string]*File) {
	for _, r := range relationships {
		if fileList[r.Parent] == nil && fileLookup[r.Parent] != nil {
			fileList[r.Parent] = fileLookup[r.Parent]
		}
		if fileList[r.Child] == nil && fileLookup[r.Child] != nil {
			fileList[r.Child] = fileLookup[r.Child]
		}
	}
}

func buildPackageMatchKeyLookup(d *Document) map[string]*Package {
	lookup := map[string]*Package{}
	for i := range d.Artifacts {
		lookup[d.Artifacts[i].UniqueID()] = &d.Artifacts[i]
	}
	return lookup
}

func buildParentRelationshipLookup(d *Document) map[string]*[]Relationship {
	lookup := map[string]*[]Relationship{}
	for _, p := range d.ArtifactRelationships {
		// Check if the lookup entry is not null
		if lookup[p.Parent] == nil {
			lookup[p.Parent] = &[]Relationship{}
		}
		addRelationshipLookupElement(lookup, p.Parent, p)
	}
	return lookup
}

func buildChildrenRelationshipLookup(d *Document) map[string]*[]Relationship {
	lookup := map[string]*[]Relationship{}
	for _, p := range d.ArtifactRelationships {
		// Check if the lookup entry is not null
		if lookup[p.Child] == nil {
			lookup[p.Child] = &[]Relationship{}
		}
		addRelationshipLookupElement(lookup, p.Child, p)
	}
	return lookup
}

func buildFileLookup(d *Document) map[string]*File {
	lookup := map[string]*File{}
	for i := range d.Files {
		lookup[d.Files[i].ID] = &d.Files[i]
	}
	return lookup
}

func addRelationshipLookupElement(lookup map[string]*[]Relationship, key string, p Relationship) {
	*lookup[key] = append(*lookup[key], Relationship{Parent: p.Parent, Child: p.Child, Type: p.Type})
}

func mapToSliceFile(m map[string]*File) []File {
	s := []File{}
	for _, v := range m {
		s = append(s, *v)
	}
	return s
}

func mapToSliceRelationship(m map[string]*Relationship) []Relationship {
	s := []Relationship{}
	for _, v := range m {
		s = append(s, *v)
	}
	return s
}
