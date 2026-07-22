package scorecard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/open-ch/grumble/syft"
)

// ErrNotFound is returned by DepsDevClient.Lookup when deps.dev has no
// record of the package/version, no GitHub source repo could be related to
// it, or the package's ecosystem isn't supported by deps.dev.
var ErrNotFound = errors.New("scorecard: package not found on deps.dev")

// depsDevSystems maps a syft purl type to the deps.dev "system" path
// segment. Ecosystems deps.dev doesn't support (e.g. gem) are absent.
//
//nolint:gochecknoglobals // immutable configuration, not mutable state
var depsDevSystems = map[string]string{
	"npm":   "npm",
	"pypi":  "pypi",
	"cargo": "cargo",
	"maven": "maven",
	"nuget": "nuget",
}

// depsDevHTTPTimeout bounds each deps.dev HTTP call.
const depsDevHTTPTimeout = 10 * time.Second

// DepsDevClient looks up precomputed Scorecard data from deps.dev
// (https://docs.deps.dev), used as the fast path before falling back to the
// Scorecard CLI.
type DepsDevClient struct {
	HTTP    *http.Client
	BaseURL string
}

type depsDevVersionResponse struct {
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType string `json:"relationType"`
	} `json:"relatedProjects"`
}

type depsDevProjectResponse struct {
	Scorecard struct {
		OverallScore float64 `json:"overallScore"`
		Checks       []struct {
			Name  string  `json:"name"`
			Score float64 `json:"score"`
		} `json:"checks"`
	} `json:"scorecard"`
}

// depsDevCheckOutcomeThreshold is the deps.dev 0-10 check score at/above
// which a check is mapped to Outcome True (below to False). deps.dev reports
// check-level scores rather than raw probes, so this is a documented
// simplification: each check becomes a single synthetic "deps.dev:<Check>"
// probe.
const depsDevCheckOutcomeThreshold = 8.0

// Lookup resolves pkg to a GitHub project via deps.dev and returns its
// precomputed Scorecard result as an Entry. It returns ErrNotFound if the
// ecosystem isn't supported by deps.dev, the package/version is unknown, or
// no GitHub source repo could be related to it.
func (c *DepsDevClient) Lookup(ctx context.Context, pkg syft.Package) (Entry, error) {
	purlType, namespace, name := parsePURL(pkg.PURL)
	system, ok := depsDevSystems[purlType]
	if !ok {
		return Entry{}, ErrNotFound
	}
	fullName := name
	if namespace != "" {
		fullName = namespace + "/" + name
	}

	version := pkg.Version
	if version == "" {
		version = purlVersion(pkg.PURL)
	}

	projectID, err := c.relatedSourceRepo(ctx, system, fullName, version)
	if err != nil {
		return Entry{}, err
	}

	return c.projectScorecard(ctx, pkg.PURL, projectID)
}

func (c *DepsDevClient) relatedSourceRepo(ctx context.Context, system, name, version string) (string, error) {
	reqURL := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s",
		c.BaseURL, system, url.PathEscape(name), url.PathEscape(version))

	var resp depsDevVersionResponse
	if err := c.getJSON(ctx, reqURL, &resp); err != nil {
		return "", err
	}

	for _, related := range resp.RelatedProjects {
		if related.RelationType == "SOURCE_REPO" && related.ProjectKey.ID != "" {
			return related.ProjectKey.ID, nil
		}
	}
	return "", ErrNotFound
}

func (c *DepsDevClient) projectScorecard(ctx context.Context, purl, projectID string) (Entry, error) {
	reqURL := fmt.Sprintf("%s/projects/%s", c.BaseURL, url.PathEscape(projectID))

	var resp depsDevProjectResponse
	if err := c.getJSON(ctx, reqURL, &resp); err != nil {
		return Entry{}, err
	}

	probes := make(map[string]Outcome, len(resp.Scorecard.Checks))
	for _, check := range resp.Scorecard.Checks {
		outcome := OutcomeFalse
		if check.Score >= depsDevCheckOutcomeThreshold {
			outcome = OutcomeTrue
		}
		probes[fmt.Sprintf("deps.dev:%s", check.Name)] = outcome
	}

	return Entry{
		Purl:         purl,
		Probes:       probes,
		RepoResolved: true,
		FetchedAtS:   time.Now().Unix(),
	}, nil
}

func (c *DepsDevClient) getJSON(ctx context.Context, reqURL string, out any) error {
	client := c.HTTP
	if client == nil {
		client = &http.Client{}
	}

	ctx, cancel := context.WithTimeout(ctx, depsDevHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build deps.dev request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call deps.dev: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("deps.dev returned status %d for %s", res.StatusCode, reqURL)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read deps.dev response: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("parse deps.dev response: %w", err)
	}
	return nil
}
