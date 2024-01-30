package syft

// IDLikes is a slice of strings that represents the IDLike field of a LinuxRelease struct.
type IDLikes []string

// LinuxRelease is a struct that represents a Linux version for a specific scanned artifact.
type LinuxRelease struct {
	PrettyName       string  `json:"prettyName,omitempty"`
	Name             string  `json:"name,omitempty"`
	ID               string  `json:"id,omitempty"`
	IDLike           IDLikes `json:"idLike,omitempty"`
	Version          string  `json:"version,omitempty"`
	VersionID        string  `json:"versionID,omitempty"`
	VersionCodename  string  `json:"versionCodename,omitempty"`
	BuildID          string  `json:"buildID,omitempty"`
	ImageID          string  `json:"imageID,omitempty"`
	ImageVersion     string  `json:"imageVersion,omitempty"`
	Variant          string  `json:"variant,omitempty"`
	VariantID        string  `json:"variantID,omitempty"`
	HomeURL          string  `json:"homeURL,omitempty"`
	SupportURL       string  `json:"supportURL,omitempty"`
	BugReportURL     string  `json:"bugReportURL,omitempty"`
	PrivacyPolicyURL string  `json:"privacyPolicyURL,omitempty"`
	CPEName          string  `json:"cpeName,omitempty"`
	SupportEnd       string  `json:"supportEnd,omitempty"`
}
