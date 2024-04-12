package format

import (
	"errors"
	"fmt"
	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/ownership"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
)

const dimensions = "{id=\"%s\",severity=\"%s\",artifact=\"%s\",licenses=\"%s\",path=\"%s\",codeowners=\"%s\"} %d"
const documentMatchValue = 1

func renderPrometheus[T PrintDocument](document T) (string, error) {
	if document, ok := any(document).(*grype.Document); ok {
		metricName := viper.GetString("prometheusMetricName")
		typeHeader := fmt.Sprintf("# TYPE %s gauge", metricName)
		metric := metricName + dimensions

		var matches []string
		keys := make(map[string]bool)
		matches = append(matches, typeHeader)
		for _, m := range document.Matches {
			render := renderMetric(metric, m, documentMatchValue)
			if _, unique := keys[render]; !unique {
				keys[render] = true
				matches = append(matches, render)
			}
		}
		return strings.Join(matches, "\n"), nil
	}
	return "", errors.New("unknown document type")
}

func renderDiffPrometheus(diff *grype.DocumentDiff) (string, error) {
	metricPrefix := viper.GetString("prometheusMetricName")
	metrics := []string{}
	renderTime := viper.GetInt64("now")

	addedMetric := metricPrefix + "_new_timestamp_seconds"
	addedStringTemplate := addedMetric + dimensions
	addedKeys := make(map[string]bool)
	metrics = append(metrics, fmt.Sprintf("# TYPE %s gauge", addedMetric))
	for _, a := range diff.Added {
		render := renderMetric(addedStringTemplate, a, renderTime)
		if _, unique := addedKeys[render]; !unique {
			addedKeys[render] = true
			metrics = append(metrics, render)
		}
	}

	removedMetric := metricPrefix + "_removed_timestamp_seconds"
	removedStringTemplate := removedMetric + dimensions
	removedKeys := make(map[string]bool)
	metrics = append(metrics, fmt.Sprintf("# TYPE %s gauge", removedMetric))
	for _, r := range diff.Removed {
		render := renderMetric(removedStringTemplate, r, renderTime)
		if _, unique := removedKeys[render]; !unique {
			removedKeys[render] = true
			metrics = append(metrics, render)
		}
	}
	return strings.Join(metrics, "\n"), nil
}

func renderMetric(metricStringTemplate string, match *grype.Match, value int64) string {
	cve := match.Vulnerability.ID
	severity := match.Vulnerability.Severity
	artifact := match.Artifact.Purl
	licenses := strings.Join(match.Artifact.Licenses, ",")
	if len(match.Artifact.Locations) != 1 {
		log.Fatal("unexpected input data only 1 location supported", "locations", len(match.Artifact.Locations), "id", cve)
	}
	path := match.Artifact.Locations[0].Path
	codeowners, err := ownership.LookupFor(path)
	if err != nil {
		log.Warn("Error looking up code owners: %s", err)
	}
	return fmt.Sprintf(metricStringTemplate, cve, severity, artifact, licenses, path, strings.Join(codeowners, ","), value)
}
