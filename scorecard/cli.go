package scorecard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrUnexpectedProbe is returned when the CLI output contains a finding for
// a probe outside ExpectedProbes, which signals a Scorecard version
// mismatch.
var ErrUnexpectedProbe = errors.New("scorecard: unexpected probe in CLI output")

// CLIReportLoader reads and validates the JSON produced by
// `scorecard --repo=<repo> --probes=<ExpectedProbes> --format=probe`.
//
// The scorecard binary itself is invoked out-of-process by a wrapping bash
// script (see platforms/cicd/ci-scripts/gsec/scanners/grumble/ci-run-grype.sh),
// not by this program; CLIReportLoader's job is only to load and validate
// the resulting probe report that script produced, on the CLI-fallback path
// after a deps.dev cache miss.
type CLIReportLoader struct {
	// ReadFile reads the file at path. Overridable for tests; defaults to
	// os.ReadFile.
	ReadFile func(path string) ([]byte, error)
}

// Load reads the CLI's `--format=probe` JSON output from path and validates
// every returned probe is one we expect, failing loudly on a Scorecard CLI
// upgrade that renamed/removed a probe.
func (l *CLIReportLoader) Load(path string) (*ProbeReport, error) {
	readFile := l.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}

	b, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scorecard cli output %s: %w", path, err)
	}

	return parseAndValidateProbeReport(b)
}

// LoadReader reads the CLI's `--format=probe` JSON output from r (e.g. when
// the wrapping script streams the output via stdin instead of writing a
// file) and validates it the same way Load does.
func (l *CLIReportLoader) LoadReader(r io.Reader) (*ProbeReport, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read scorecard cli output: %w", err)
	}
	return parseAndValidateProbeReport(b)
}

// ProbesFlag renders ExpectedProbes as the comma-separated value the
// wrapping bash script should pass to `scorecard --probes=`.
func ProbesFlag() string {
	return strings.Join(ExpectedProbes, ",")
}

func parseAndValidateProbeReport(b []byte) (*ProbeReport, error) {
	report, err := ParseProbeReport(b)
	if err != nil {
		return nil, err
	}

	expected := make(map[string]bool, len(ExpectedProbes))
	for _, p := range ExpectedProbes {
		expected[p] = true
	}
	for _, f := range report.Findings {
		if !expected[f.Probe] {
			return nil, fmt.Errorf("%w: %q", ErrUnexpectedProbe, f.Probe)
		}
	}

	return report, nil
}
