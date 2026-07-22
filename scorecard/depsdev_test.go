package scorecard

import (
	"context"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"

	"github.com/open-ch/grumble/syft"
)

const depsDevBaseURL = "https://api.deps.dev/v3"

func TestDepsDevClientLookup(t *testing.T) {
	tests := []struct {
		name        string
		pkg         syft.Package
		setupMocks  func()
		wantErr     error
		wantLicense string
		wantOutcome map[string]Outcome
	}{
		{
			name: "npm package resolves via related project and scorecard",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "npm",
				Name: "lodash",
				PURL: "pkg:npm/lodash@4.17.21",
			}},
			setupMocks: func() {
				httpmock.RegisterResponder("GET", depsDevBaseURL+"/systems/npm/packages/lodash/versions/4.17.21",
					httpmock.NewStringResponder(200, `{
						"relatedProjects": [
							{"projectKey": {"id": "github.com/lodash/lodash"}, "relationType": "SOURCE_REPO"}
						]
					}`))
				httpmock.RegisterResponder("GET", depsDevBaseURL+"/projects/github.com%2Flodash%2Flodash",
					httpmock.NewStringResponder(200, `{
						"scorecard": {
							"overallScore": 6.5,
							"checks": [
								{"name": "License", "score": 10},
								{"name": "Maintained", "score": 3}
							]
						}
					}`))
			},
			wantOutcome: map[string]Outcome{
				"deps.dev:License":    OutcomeTrue,
				"deps.dev:Maintained": OutcomeFalse,
			},
		},
		{
			name: "package not found on deps.dev",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "npm",
				Name: "totally-unknown-package",
				PURL: "pkg:npm/totally-unknown-package@1.0.0",
			}},
			setupMocks: func() {
				httpmock.RegisterResponder("GET", depsDevBaseURL+"/systems/npm/packages/totally-unknown-package/versions/1.0.0",
					httpmock.NewStringResponder(404, `{}`))
			},
			wantErr: ErrNotFound,
		},
		{
			name: "no source repo related project",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "pypi",
				Name: "somepkg",
				PURL: "pkg:pypi/somepkg@1.0.0",
			}},
			setupMocks: func() {
				httpmock.RegisterResponder("GET", depsDevBaseURL+"/systems/pypi/packages/somepkg/versions/1.0.0",
					httpmock.NewStringResponder(200, `{"relatedProjects": []}`))
			},
			wantErr: ErrNotFound,
		},
		{
			name: "unsupported ecosystem",
			pkg: syft.Package{PackageBasicData: syft.PackageBasicData{
				Type: "gem",
				Name: "somegem",
				PURL: "pkg:gem/somegem@1.0.0",
			}},
			setupMocks: func() {},
			wantErr:    ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, "not found"))
			tt.setupMocks()

			client := &DepsDevClient{HTTP: &http.Client{}, BaseURL: depsDevBaseURL}
			entry, err := client.Lookup(context.Background(), tt.pkg)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.True(t, entry.RepoResolved)
			require.Equal(t, tt.wantOutcome, entry.Probes)
		})
	}
}
