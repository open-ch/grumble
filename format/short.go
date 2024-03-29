package format

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/grype"
)

func renderShort(document *grype.Document) (string, error) {
	if len(document.Matches) == 0 {
		return "No matches in document", nil
	}

	var matches []string
	for _, m := range document.Matches {
		render := RenderMatchShort(m)
		matches = append(matches, render)
	}

	return styles.reportBox.Render(lipgloss.JoinVertical(lipgloss.Left, matches...)), nil
}

// RenderMatchShort Renders a match as a single line of colored text
func RenderMatchShort(match *grype.Match) string {
	initStyles()
	cve := match.Vulnerability.ID
	if len(match.Artifact.Locations) != 1 {
		log.Fatal("unexpected input data only 1 location supported", "locations", len(match.Artifact.Locations), "id", cve)
	}
	path := match.Artifact.Locations[0].Path

	return lipgloss.JoinHorizontal(lipgloss.Top,
		renderSeverity(match.Vulnerability.Severity),
		styles.bold.PaddingRight(1).Render(match.Artifact.Purl),
		styles.constrast.Render(path),
		styles.faint.PaddingLeft(1).Render(cve),
	)
}
