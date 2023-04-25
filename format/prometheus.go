package format

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/ownership"
)

const dimensions = "{id=\"%s\",severity=\"%s\",artifact=\"%s\",licenses=\"%s\",path=\"%s\",codeowners=\"%s\"} 1"

func renderPrometheus(document *grype.Document) (string, error) {
	metricName := viper.GetString("prometheusMetricName")
	typeHeader := fmt.Sprintf("# TYPE %s gauge", metricName)
	metric := metricName + dimensions

	var matches []string
	keys := make(map[string]bool)
	matches = append(matches, typeHeader)
	for _, match := range document.Matches {
		render := renderMetric(metric, &match)
		if _, unique := keys[render]; !unique {
			keys[render] = true
			matches = append(matches, render)
		}
	}
	return strings.Join(matches, "\n"), nil
}

func renderMetric(metric string, match *grype.Match) string {
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
	return fmt.Sprintf(metric, id, severity, artifact, licenses, path, strings.Join(codeowners, ","))
}
