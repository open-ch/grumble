package scorecard

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-ch/grumble/syft"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		pkg     syft.Package
		wantRef RepoRef
		wantOK  bool
	}{
		{
			name: "golang purl hosted directly on github resolves",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "go-module",
				PURL: "pkg:golang/github.com/ossf/scorecard@v5.5.0",
			}},
			wantRef: RepoRef{Host: "github.com", Owner: "ossf", Name: "scorecard"},
			wantOK:  true,
		},
		{
			name: "golang purl with nested import path uses last owner/name pair",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "go-module",
				PURL: "pkg:golang/github.com/open-systems-sase/panta/tools/grumble@v0.0.0",
			}},
			wantRef: RepoRef{Host: "github.com", Owner: "open-systems-sase", Name: "panta"},
			wantOK:  true,
		},
		{
			name: "golang purl not hosted on github is not directly resolvable but eligible",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "go-module",
				PURL: "pkg:golang/golang.org/x/net@v0.30.0",
			}},
			wantRef: RepoRef{},
			wantOK:  true,
		},
		{
			name: "npm purl is eligible via deps.dev but not directly resolvable",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "npm",
				PURL: "pkg:npm/lodash@4.17.21",
			}},
			wantRef: RepoRef{},
			wantOK:  true,
		},
		{
			name: "scoped npm purl is eligible",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "npm",
				PURL: "pkg:npm/%40angular/core@17.0.0",
			}},
			wantRef: RepoRef{},
			wantOK:  true,
		},
		{
			name: "pypi purl is eligible",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "python",
				PURL: "pkg:pypi/django@4.2.0",
			}},
			wantRef: RepoRef{},
			wantOK:  true,
		},
		{
			name: "cargo purl is eligible",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "rust-crate",
				PURL: "pkg:cargo/rand@0.8.5",
			}},
			wantRef: RepoRef{},
			wantOK:  true,
		},
		{
			name: "maven purl is eligible",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "java-archive",
				PURL: "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			}},
			wantRef: RepoRef{},
			wantOK:  true,
		},
		{
			name: "deb purl is skipped as non-github/OS package",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "deb",
				PURL: "pkg:deb/debian/curl@7.74.0",
			}},
			wantRef: RepoRef{},
			wantOK:  false,
		},
		{
			name: "rpm purl is skipped",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "rpm",
				PURL: "pkg:rpm/centos/bash@4.4.20",
			}},
			wantRef: RepoRef{},
			wantOK:  false,
		},
		{
			name: "empty purl is skipped",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "unknown",
				PURL: "",
			}},
			wantRef: RepoRef{},
			wantOK:  false,
		},
		{
			name: "internal osag generic package is skipped",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "generic",
				PURL: "pkg:generic/osag/internal-tool@1.0.0",
			}},
			wantRef: RepoRef{},
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, ok := Resolve(tt.pkg)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantRef, ref)
		})
	}
}

func TestRepoRefString(t *testing.T) {
	ref := RepoRef{Host: "github.com", Owner: "ossf", Name: "scorecard"}
	require.Equal(t, "github.com/ossf/scorecard", ref.String())
}
