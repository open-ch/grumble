package format

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/ownership"
)

const dimensions = "{id=\"%s\",severity=\"%s\",artifact=\"%s\",licenses=\"%s\",path=\"%s\",codeowners=\"%s\"} %d"
const documentMatchValue = 1

func renderPrometheus(document *grype.Document) (string, error) {
	metricName := viper.GetString("prometheusMetricName")
	typeHeader := fmt.Sprintf("# TYPE %s gauge", metricName)
	metric := metricName + dimensions

	var matches []string
	keys := make(map[string]bool)
	matches = append(matches, typeHeader)
	for _, match := range document.Matches {
		render := renderMetric(metric, &match, documentMatchValue)
		if _, unique := keys[render]; !unique {
			keys[render] = true
			matches = append(matches, render)
		}
	}
	return strings.Join(matches, "\n"), nil
}

func renderDiffPrometheus(diff *grype.DocumentDiff) (string, error) {
	metricPrefix := viper.GetString("prometheusMetricName")
	metrics := []string{}
	renderTime := viper.GetInt64("now")

	addedMetric := metricPrefix + "_new_timestamp_seconds"
	addedStringTemplate := addedMetric + dimensions
	addedKeys := make(map[string]bool)
	metrics = append(metrics, fmt.Sprintf("# TYPE %s gauge", addedMetric))
	for _, match := range diff.Added {
		render := renderMetric(addedStringTemplate, &match, renderTime)
		if _, unique := addedKeys[render]; !unique {
			addedKeys[render] = true
			metrics = append(metrics, render)
		}
	}

	removedMetric := metricPrefix + "_removed_timestamp_seconds"
	removedStringTemplate := removedMetric + dimensions
	removedKeys := make(map[string]bool)
	metrics = append(metrics, fmt.Sprintf("# TYPE %s gauge", removedMetric))
	for _, match := range diff.Removed {
		render := renderMetric(removedStringTemplate, &match, renderTime)
		if _, unique := removedKeys[render]; !unique {
			removedKeys[render] = true
			metrics = append(metrics, render)
		}
	}
	return strings.Join(metrics, "\n"), nil
}

func renderMetric(metricStringTemplate string, match *grype.Match, value int64) string {
	id := match.Vulnerability.ID
	severity := match.Vulnerability.Severity
	artifact := match.Artifact.Purl
	licenses := strings.Join(match.Artifact.Licenses, ",")
	if len(match.Artifact.Locations) != 1 {
		log.Fatal("unexpected input data, only 1 location supported", "locations", len(match.Artifact.Locations))
	}
	path := match.Artifact.Locations[0].Path
	codeowners, err := ownership.LookupFor(path)
	if err != nil {
		log.Warn("Error looking up code owners: %s", err)
	}
	return fmt.Sprintf(metricStringTemplate, id, severity, artifact, licenses, path, strings.Join(codeowners, ","), value)
}
