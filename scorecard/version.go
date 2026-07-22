package scorecard

// PinnedCLIVersion is the OSSF Scorecard CLI version pinned in the smith-agent
// image (see platforms/cicd/images/smith-agent/Dockerfile). Keep in sync: if
// the CLI is upgraded, bump this constant and re-verify ExpectedProbes below
// still matches the probes the new version reports.
const PinnedCLIVersion = "5.5.0"

// ExpectedProbes is the pinned set of Scorecard probes requested via
// `--probes=` and expected back in `--format=probe` output. Keeping this
// explicit (rather than requesting all probes) limits the work Scorecard has
// to do and lets us fail loudly in tests if an upgrade renames/removes one of
// these probes.
//
//nolint:gochecknoglobals // immutable configuration, not mutable state
var ExpectedProbes = []string{
	// maintenance signals
	"archived",
	"notArchived",
	"hasRecentCommits",
	"issueActivityByProjectMember",
	// license signals
	"hasLicenseFile",
	"hasFSFOrOSIApprovedLicense",
	"hasOSIApprovedLicense",
}
