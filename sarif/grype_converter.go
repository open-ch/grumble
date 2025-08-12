package sarif

import (
	"fmt"
	"log"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/open-ch/grumble/grype"
)

// GrypeSeverity represents the severity levels used by Grype
type GrypeSeverity string

const (
	GrypeSeverityCritical   GrypeSeverity = "critical"
	GrypeSeverityHigh       GrypeSeverity = "high"
	GrypeSeverityMedium     GrypeSeverity = "medium"
	GrypeSeverityLow        GrypeSeverity = "low"
	GrypeSeverityNegligible GrypeSeverity = "negligible"
)

// Level represents the severity levels used in SARIF format
type Level string

const (
	Error   Level = "error"
	Warning Level = "warning"
	Note    Level = "note"
)

// GrypeToSARIF converts a Grype vulnerability report to SARIF format
//
//nolint:cyclop
func GrypeToSARIF(grypeDoc *grype.Document) (*sarif.Report, error) {
	if grypeDoc == nil {
		return nil, fmt.Errorf("grype document cannot be nil")
	}

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, fmt.Errorf("failed to create SARIF report: %w", err)
	}

	// Create the tool component for Grype
	driver := sarif.NewDriver("grype")
	informationURI := "https://github.com/anchore/grype"
	driver.InformationURI = &informationURI
	driver.Version = &grypeDoc.Descriptor.Version

	// Add rules for each unique vulnerability
	rules := make(map[string]*sarif.ReportingDescriptor)
	for _, match := range grypeDoc.Matches {
		if _, exists := rules[match.Vulnerability.ID]; !exists {
			rule := createRuleFromVulnerability(&match.Vulnerability)
			rules[match.Vulnerability.ID] = rule
			driver.Rules = append(driver.Rules, rule)
		}
	}

	// Add rules for ignored matches too
	for _, match := range grypeDoc.IgnoredMatches {
		if _, exists := rules[match.Vulnerability.ID]; !exists {
			rule := createRuleFromVulnerability(&match.Vulnerability)
			rules[match.Vulnerability.ID] = rule
			driver.Rules = append(driver.Rules, rule)
		}
	}

	tool := sarif.NewTool(driver)
	run := sarif.NewRun(*tool)

	// Convert each match to a SARIF result
	for _, match := range grypeDoc.Matches {
		result, err := convertMatchToResult(match)
		if err != nil {
			return nil, fmt.Errorf("failed to convert match to SARIF result: %w", err)
		}
		run.Results = append(run.Results, result)
	}

	// Add ignored matches as suppressed results
	for _, match := range grypeDoc.IgnoredMatches {
		result, err := convertMatchToResult(match)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ignored match to SARIF result: %w", err)
		}

		// Mark as suppressed with ignore rules as justification
		suppression := sarif.NewSuppression("inSource")
		if len(match.AppliedIgnoreRules) > 0 {
			justification := "Applied ignore rules: "
			for i := range match.AppliedIgnoreRules {
				if i > 0 {
					justification += ", "
				}
				justification += match.AppliedIgnoreRules[i].Vulnerability
			}
			suppression.Justification = &justification
		}
		result.Suppressions = []*sarif.Suppression{suppression}

		run.Results = append(run.Results, result)
	}

	report.Runs = append(report.Runs, run)
	return report, nil
}

// convertMatchToResult converts a Grype match to a SARIF result
func convertMatchToResult(match *grype.Match) (*sarif.Result, error) {
	if match == nil {
		return nil, fmt.Errorf("match cannot be nil")
	}

	result := sarif.NewRuleResult(match.Vulnerability.ID)
	message := sarif.NewTextMessage(match.Vulnerability.Description)
	result.Message = *message

	// Set severity level based on vulnerability severity
	level := convertSeverityToLevel(match.Vulnerability.Severity)
	result.Level = &level

	// Add locations for each artifact location
	for _, location := range match.Artifact.Locations {
		if location.Path == "" {
			continue
		}

		// Create physical location
		physicalLocation := sarif.NewPhysicalLocation()
		physicalLocation.ArtifactLocation = sarif.NewSimpleArtifactLocation(location.Path)

		sarifLocation := sarif.NewLocation()
		sarifLocation.PhysicalLocation = physicalLocation
		result.Locations = append(result.Locations, sarifLocation)
	}

	// If no locations found, create a logical location based on the artifact
	if len(result.Locations) == 0 {
		logicalLocation := sarif.NewLogicalLocation()
		artifactName := match.Artifact.Name
		fullyQualifiedName := fmt.Sprintf("%s@%s", match.Artifact.Name, match.Artifact.Version)
		logicalLocation.Name = &artifactName
		logicalLocation.FullyQualifiedName = &fullyQualifiedName

		sarifLocation := sarif.NewLocation()
		sarifLocation.LogicalLocations = []*sarif.LogicalLocation{logicalLocation}
		result.Locations = append(result.Locations, sarifLocation)
	}

	// Add additional properties
	properties := make(map[string]any)
	properties["packageName"] = match.Artifact.Name
	properties["packageVersion"] = match.Artifact.Version
	properties["packageType"] = match.Artifact.Type
	properties["packageLanguage"] = match.Artifact.Language
	properties["packagePURL"] = match.Artifact.Purl

	if len(match.Artifact.CPEs) > 0 {
		properties["cpes"] = match.Artifact.CPEs
	}

	if len(match.Vulnerability.CVSS) > 0 {
		cvss := match.Vulnerability.CVSS[0] // Use first CVSS score
		properties["cvssScore"] = cvss.Metrics.BaseScore
		properties["cvssVector"] = cvss.Vector
		properties["cvssVersion"] = cvss.Version
	}

	if match.Vulnerability.Fix.State != "" {
		properties["fixState"] = match.Vulnerability.Fix.State
		if len(match.Vulnerability.Fix.Versions) > 0 {
			properties["fixVersions"] = match.Vulnerability.Fix.Versions
		}
	}

	result.Properties = properties

	return result, nil
}

// createRuleFromVulnerability creates a SARIF rule from a Grype vulnerability
func createRuleFromVulnerability(vuln *grype.Vulnerability) *sarif.ReportingDescriptor {
	rule := sarif.NewRule(vuln.ID)
	rule.ShortDescription = sarif.NewMultiformatMessageString(vuln.ID)
	rule.FullDescription = sarif.NewMultiformatMessageString(vuln.Description)

	// Set default configuration based on severity
	level := convertSeverityToLevel(vuln.Severity)
	defaultConfig := sarif.NewReportingConfiguration()
	defaultConfig.Level = level
	rule.DefaultConfiguration = defaultConfig

	// Add help information
	//nolint: nestif
	if len(vuln.Urls) > 0 {
		helpURI := vuln.Urls[0] // Use first URL as primary help
		rule.HelpURI = &helpURI

		// Create help text with all URLs
		var helpText strings.Builder
		_, err := helpText.WriteString(fmt.Sprintf("Vulnerability %s\n\n", vuln.ID))
		if err != nil {
			log.Fatalf("Cannot write vulnerability field: %s", err.Error())
		}
		_, err = helpText.WriteString(fmt.Sprintf("Severity: %s\n", vuln.Severity))
		if err != nil {
			log.Fatalf("Cannot write severity field: %s", err.Error())
		}
		_, err = helpText.WriteString(fmt.Sprintf("Data Source: %s\n\n", vuln.DataSource))
		if err != nil {
			log.Fatalf("Cannot write data source field: %s", err.Error())
		}

		if vuln.Description != "" {
			_, err = helpText.WriteString(fmt.Sprintf("Description: %s\n\n", vuln.Description))
			if err != nil {
				log.Fatalf("Cannot write description  field: %s", err.Error())
			}
		}

		_, err = helpText.WriteString("References:\n")
		if err != nil {
			log.Fatalf("Cannot write references field: %s", err.Error())
		}
		for _, url := range vuln.Urls {
			_, err = helpText.WriteString(fmt.Sprintf("- %s\n", url))
			if err != nil {
				log.Fatalf("Cannot write urls field: %s", err.Error())
			}
		}

		rule.Help = sarif.NewMultiformatMessageString(helpText.String())
	}

	// Add properties for additional metadata
	properties := make(map[string]any)
	properties["severity"] = vuln.Severity
	properties["dataSource"] = vuln.DataSource
	properties["namespace"] = vuln.Namespace

	if len(vuln.CVSS) > 0 {
		cvss := vuln.CVSS[0]
		properties["cvssScore"] = cvss.Metrics.BaseScore
		properties["cvssVector"] = cvss.Vector
		properties["cvssVersion"] = cvss.Version
	}

	rule.Properties = properties

	return rule
}

// convertSeverityToLevel converts Grype severity to SARIF level
func convertSeverityToLevel(severity string) string {
	switch GrypeSeverity(strings.ToLower(severity)) {
	case GrypeSeverityCritical:
		return string(Error)
	case GrypeSeverityHigh:
		return string(Error)
	case GrypeSeverityMedium:
		return string(Warning)
	case GrypeSeverityLow:
		return string(Note)
	case GrypeSeverityNegligible:
		return string(Note)
	default:
		return string(Warning)
	}
}
