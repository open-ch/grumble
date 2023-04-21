package format

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/ownership"
)

func renderPretty(document *grype.Document) (string, error) {
	highlight := lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special := lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	emptyBox := lipgloss.NewStyle().
		Foreground(special).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(highlight).
		PaddingLeft(4).
		PaddingRight(4)

	reportBox := lipgloss.NewStyle()

	if len(document.Matches) == 0 {
		return emptyBox.Render(lipgloss.JoinVertical(lipgloss.Left,
			"No matches in document",
			getSquirel(),
		)), nil
	}

	var matches []string
	for _, match := range document.Matches {
		render := renderMatchPretty(&match)
		matches = append(matches, render)
	}
	return reportBox.Render(lipgloss.JoinVertical(lipgloss.Left,
		matches...,
	)), nil
}

func renderMatchPretty(match *grype.Match) string {
	width := 120 // TODO look up current session with
	// TODO define colors for the different levels of vunlnerabilities?
	plainStyle := lipgloss.NewStyle().Faint(true)
	purlStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#B9BFCA")).PaddingRight(1)
	sevStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("178")).PaddingRight(1).
		Width(9) // Critical is the longest one
	matchBox := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		Width(width)

	vid := match.Vulnerability.ID
	severity := match.Vulnerability.Severity
	description := match.Vulnerability.Description
	aname := match.Artifact.Purl
	// TODO join all locations into 1 string, + handle 0 if there could be more than 1?
	apaths := match.Artifact.Locations[0].Path
	codeowners, err := ownership.LookupFor(apaths)
	if err != nil {
		codeowners = fmt.Sprintf("Error looking up code owners: %s", err)
	}

	return matchBox.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Top,
				sevStyle.Render(severity),
				purlStyle.Render(aname),
				plainStyle.Render(vid),
			),
			plainStyle.Render(description),
			plainStyle.Render(fmt.Sprintf("Path: %s", apaths)),
			plainStyle.Render(fmt.Sprintf("Code owners: %s", codeowners)),
		))
}

func getSquirel() string {
	return ` (\__/)  .~    ~. ))
 /O O  ./      .'
{O__,   \    {
  / .  . )    \
  |-| '-' \    }
 .(   _(   )_.'
'---.~_ _ _&`
}
