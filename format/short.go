package format

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/grype"
)

func renderShort(document *grype.Document) (string, error) {
	styles = makeStyles()
	if len(document.Matches) == 0 {
		return "No matches in document", nil
	}

	var matches []string
	for _, match := range document.Matches {
		render := renderOneLine(&match)
		matches = append(matches, render)
	}

	return styles.reportBox.Render(lipgloss.JoinVertical(lipgloss.Left, matches...)), nil
}

func renderOneLine(match *grype.Match) string {
	cve := match.Vulnerability.ID
	if len(match.Artifact.Locations) != 1 {
		log.Fatal("unexpected input data, only 1 location supported", "locations", len(match.Artifact.Locations))
	}
	path := match.Artifact.Locations[0].Path

	return lipgloss.JoinHorizontal(lipgloss.Top,
		renderSeverity(match.Vulnerability.Severity),
		styles.bold.PaddingRight(1).Render(match.Artifact.Purl),
		styles.constrast.Render(path),
		styles.faint.PaddingLeft(1).Render(cve),
	)
}
