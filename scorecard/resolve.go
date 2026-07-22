package scorecard

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/syft"
)

// RepoRef identifies the GitHub repository a package's source lives in.
type RepoRef struct {
	Host  string
	Owner string
	Name  string
}

// String renders the ref as "host/owner/name".
func (r RepoRef) String() string {
	return fmt.Sprintf("%s/%s/%s", r.Host, r.Owner, r.Name)
}

// depsDevEcosystems are purl types whose packages cannot be mapped to a
// GitHub repo from the purl alone, but that deps.dev can map to a Scorecard
// result for (see depsdev.go).
//
//nolint:gochecknoglobals // immutable configuration, not mutable state
var depsDevEcosystems = map[string]bool{
	"npm":   true,
	"pypi":  true,
	"cargo": true,
	"gem":   true,
	"maven": true,
	"nuget": true,
}

// Resolve determines whether a package is eligible for Scorecard enrichment,
// and if its source repo can be determined directly from the purl (golang
// packages hosted on github.com), returns the RepoRef to use.
//
// For ecosystems that require a deps.dev project lookup (npm, pypi, cargo,
// gem, maven, nuget) Resolve returns an empty RepoRef with ok=true: the
// caller is expected to fall back to DepsDevClient.Lookup using the package
// itself. Non-GitHub, OS-level (deb/rpm/apk) and unrecognized/internal
// packages are skipped (ok=false) with a logged warning.
func Resolve(pkg syft.Package) (RepoRef, bool) {
	purlType, namespace, name := parsePURL(pkg.PURL)

	switch {
	case purlType == "golang" && isGithubNamespace(namespace):
		if owner, repo, ok := githubOwnerAndRepo(namespace, name); ok {
			return RepoRef{Host: "github.com", Owner: owner, Name: repo}, true
		}
	case purlType == "golang":
		// Not hosted directly on github.com (e.g. golang.org/x/net); leave
		// resolution to the deps.dev fallback.
		return RepoRef{}, true
	case purlType == "github":
		if owner, repo, ok := githubOwnerAndRepo(namespace, name); ok {
			return RepoRef{Host: "github.com", Owner: owner, Name: repo}, true
		}
	case depsDevEcosystems[purlType]:
		return RepoRef{}, true
	}

	log.Warn("scorecard: skipping package with no github mapping", "name", pkg.Name, "purl", pkg.PURL)
	return RepoRef{}, false
}

// isGithubNamespace reports whether a golang purl namespace points at
// github.com, e.g. "github.com/ossf".
func isGithubNamespace(namespace string) bool {
	return namespace == "github.com" || strings.HasPrefix(namespace, "github.com/")
}

// githubOwnerAndRepo extracts the "owner/repo" pair from a golang purl's
// namespace+name, which may include a nested import path beyond the repo
// root (e.g. "github.com/open-systems-sase/panta" + "tools/grumble").
func githubOwnerAndRepo(namespace, name string) (owner, repo string, ok bool) {
	segments := strings.Split(strings.TrimPrefix(namespace, "github.com/"), "/")
	fullPath := append(append([]string{}, segments...), strings.Split(name, "/")...)
	if len(fullPath) < 2 || fullPath[0] == "" {
		return "", "", false
	}
	return fullPath[0], fullPath[1], true
}

// parsePURL extracts the type, namespace and name from a package URL
// (https://github.com/package-url/purl-spec), ignoring version, qualifiers
// and subpath, which scorecard resolution doesn't need.
func parsePURL(purl string) (purlType, namespace, name string) {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", ""
	}
	rest := purl[len(prefix):]

	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}

	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", "", ""
	}
	purlType = rest[:slash]
	path := rest[slash+1:]

	if i := strings.IndexByte(path, '@'); i >= 0 {
		path = path[:i]
	}

	lastSlash := strings.LastIndexByte(path, '/')
	if lastSlash < 0 {
		name = unescapePURLSegment(path)
		return purlType, "", name
	}
	namespace = unescapePURLSegment(path[:lastSlash])
	name = unescapePURLSegment(path[lastSlash+1:])
	return purlType, namespace, name
}

// purlVersion extracts the version segment of a purl (between '@' and any
// qualifiers/subpath), or "" if absent.
func purlVersion(purl string) string {
	rest := purl
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return ""
	}
	return unescapePURLSegment(rest[at+1:])
}

func unescapePURLSegment(s string) string {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}
