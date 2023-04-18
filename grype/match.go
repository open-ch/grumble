package grype

// Match info of a grype document's matches
type Match struct {
	Artifact               Artifact               `json:"artifact"`
	MatchDetails           []MatchDetail          `json:"matchDetails"`
	RelatedVulnerabilities []RelatedVulnerability `json:"relatedVulnerabilities"`
	Vulnerability          Vulnerability          `json:"vulnerability"`
}

// Artifact info about a match
type Artifact struct {
	CPEs         []string   `json:"cpes"`
	Language     string     `json:"language"`
	Licenses     []string   `json:"licenses"`
	Locations    []Location `json:"locations"`
	Metadata     *Metadata  `json:"metadata,omitempty"`
	MetadataType string     `json:"metadataType,omitempty"`
	Name         string     `json:"name"`
	Purl         string     `json:"purl"`
	Type         string     `json:"type"`
	Upstreams    []any      `json:"upstreams"`
	Version      string     `json:"version"`
}

// MatchDetail detailed additional info about a match
type MatchDetail struct {
	Found      Found      `json:"found"`
	Matcher    string     `json:"matcher"`
	SearchedBy SearchedBy `json:"searchedBy"`
	Type       string     `json:"type"`
}

// RelatedVulnerability info about a match related vulns
type RelatedVulnerability struct {
	CVSS        []CVSS   `json:"cvss"`
	DataSource  string   `json:"dataSource"`
	Description string   `json:"description"`
	ID          string   `json:"id"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity,omitempty"`
	Urls        []string `json:"urls"`
}

// Vulnerability info about a match
type Vulnerability struct {
	Advisories  []any    `json:"advisories"`
	CVSS        []CVSS   `json:"cvss"`
	DataSource  string   `json:"dataSource"`
	Description string   `json:"description"`
	Fix         Fix      `json:"fix"`
	ID          string   `json:"id"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	Urls        []string `json:"urls"`
}

// Location holds the path of a given artifact
type Location struct {
	Path string `json:"path"`
}

// Metadata about a given artifact
type Metadata *struct {
	ArchiveDigests []ArchiveDigest `json:"archiveDigests,omitempty"`
	H1Digest       string          `json:"h1Digest,omitempty"`
	ManifestName   string          `json:"manifestName"`
	PomArtifactID  string          `json:"pomArtifactID"`
	PomGroupID     string          `json:"pomGroupID"`
	VirtualPath    string          `json:"virtualPath,omitempty"`
}

// ArchiveDigest metadata of an artifacact aka checksum info
type ArchiveDigest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Found Common Platform Enumeration (CPE) info about a match detail
type Found struct {
	CPEs              []string `json:"cpes,omitempty"`
	VersionConstraint string   `json:"versionConstraint"`
	VulnerabilityID   string   `json:"vulnerabilityID"`
}

// SearchedBy Common Platform Enumeration (CPE) info about a match detail
type SearchedBy struct {
	CPEs      []string `json:"cpes,omitempty"`
	Language  string   `json:"language,omitempty"`
	Namespace string   `json:"namespace"`
}

// CVSS Common Vulnerability Scoring System info
type CVSS struct {
	Metrics        Metrics        `json:"metrics"`
	Vector         string         `json:"vector"`
	VendorMetadata VendorMetadata `json:"vendorMetadata"`
	Version        string         `json:"version"`
}

// Fix details if and at what version a fix is available for a vulnerability
type Fix struct {
	State    string   `json:"state"`
	Versions []string `json:"versions"`
}

// Metrics stores vulnerability scores
type Metrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// VendorMetadata info about the vendor of a software from a vulnerability.
type VendorMetadata struct{}
