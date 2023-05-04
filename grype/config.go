package grype

//revive:disable:nested-structs

// IgnoreRule vulnerability ignore rule, either for descriptor of configured rules
// or added as AppliedIgnoreRules to an ignored vulnerability
//
// Note: While using the same definition grype as of version 0.59.0 is not consistent:
// - Rules listed in ignoredMatches[].AppliedIgnoreRules omit empty fields
// - Rules listed in descriptor.ignore use empty strings but do not omit empty fields.
// Here we opt for omit empty, but a grype document processed with grumble with no filters
// might be modified in that aspect.
//
// See also https://github.com/anchore/grype#specifying-matches-to-ignore.
type IgnoreRule struct {
	Vulnerability string `json:"vulnerability"`
	Namespace     string `json:"namespace,omitempty"`
	FixState      string `json:"fix-state,omitempty"`
	Package       struct {
		Name     string `json:"name,omitempty"`
		Version  string `json:"version,omitempty"`
		Language string `json:"language,omitempty"`
		Type     string `json:"type,omitempty"`
		Location string `json:"location,omitempty"`
	} `json:"package,omitempty"`
}
