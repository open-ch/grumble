package scorecard

import (
	"encoding/json"
	"fmt"
)

// Outcome is the result of a single Scorecard probe, mirroring
// github.com/ossf/scorecard/v5/finding.Outcome.
type Outcome string

// Known probe outcomes as emitted by `scorecard --format=probe`.
const (
	OutcomeTrue          Outcome = "True"
	OutcomeFalse         Outcome = "False"
	OutcomeNotApplicable Outcome = "NotApplicable"
	OutcomeError         Outcome = "Error"
	OutcomeNotAvailable  Outcome = "NotAvailable"
	OutcomeNotSupported  Outcome = "NotSupported"
)

// IsNeutral reports whether the outcome should be treated as a neutral pass:
// it never lowers a score and never blocks a gate. This covers outcomes where
// Scorecard could not determine an answer (Error, NotAvailable), and outcomes
// where the probe's question doesn't apply to this probe (NotApplicable,
// NotSupported). Unknown/future outcomes are also treated as neutral so a
// Scorecard upgrade fails safe rather than unexpectedly blocking builds.
func (o Outcome) IsNeutral() bool {
	switch o {
	case OutcomeTrue, OutcomeFalse:
		return false
	case OutcomeNotApplicable, OutcomeError, OutcomeNotAvailable, OutcomeNotSupported:
		return true
	default:
		return true
	}
}

// Finding is a single probe result: which probe ran and its outcome.
type Finding struct {
	Probe   string  `json:"probe"`
	Outcome Outcome `json:"outcome"`
}

// ProbeReport is the parsed result of `scorecard --repo=<repo> --format=probe`.
type ProbeReport struct {
	Repo     string
	Findings []Finding
}

// probeReportJSON mirrors the raw JSON shape emitted by the Scorecard CLI
// (github.com/ossf/scorecard/v5/pkg/scorecard.JSONScorecardProbeResult). Only
// the fields we use are declared.
type probeReportJSON struct {
	Repo struct {
		Name string `json:"name"`
	} `json:"repo"`
	Findings []Finding `json:"findings"`
}

// ParseProbeReport parses the JSON output of `scorecard --format=probe` (from
// either the CLI or a cached copy) into a ProbeReport.
func ParseProbeReport(b []byte) (*ProbeReport, error) {
	var raw probeReportJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse scorecard probe report: %w", err)
	}

	return &ProbeReport{
		Repo:     raw.Repo.Name,
		Findings: raw.Findings,
	}, nil
}

// Probes returns the findings as a probe-name -> outcome map for convenient
// lookup by policy derivation.
func (r ProbeReport) Probes() map[string]Outcome {
	out := make(map[string]Outcome, len(r.Findings))
	for _, f := range r.Findings {
		out[f.Probe] = f.Outcome
	}
	return out
}
