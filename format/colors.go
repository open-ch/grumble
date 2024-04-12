package format

import (
	"fmt"
	"github.com/open-ch/grumble/grype"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

type colorScheme struct {
	name      string
	highlight lipgloss.AdaptiveColor
	special   lipgloss.AdaptiveColor
	good      lipgloss.AdaptiveColor
	neutral   lipgloss.AdaptiveColor
	bad       lipgloss.AdaptiveColor

	critical lipgloss.AdaptiveColor
	high     lipgloss.AdaptiveColor
	medium   lipgloss.AdaptiveColor
	low      lipgloss.AdaptiveColor

	background         lipgloss.AdaptiveColor
	contrast           lipgloss.AdaptiveColor
	backgroundContrast lipgloss.AdaptiveColor
}

const lipglossStyleWidth = 15
const lipglossStylePadding = 1

//nolint:gochecknoglobals // not worth refactoring at the moment
var colors = colorScheme{
	name:      "default",
	highlight: lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"},
	special:   lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"},
	good:      lipgloss.AdaptiveColor{Light: "#485e30", Dark: "#9ece6a"},
	neutral:   lipgloss.AdaptiveColor{Light: "#5a4a78", Dark: "#bb9af7"},
	bad:       lipgloss.AdaptiveColor{Light: "#8c4351", Dark: "#f7768e"},

	// Severity
	critical: lipgloss.AdaptiveColor{Light: "#8c4351", Dark: "#f7768e"},
	high:     lipgloss.AdaptiveColor{Light: "#965027", Dark: "#ff9e64"},
	medium:   lipgloss.AdaptiveColor{Light: "#8f5e15", Dark: "#e0af68"},
	low:      lipgloss.AdaptiveColor{Light: "#33635c", Dark: "#73daca"},

	background:         lipgloss.AdaptiveColor{Light: "#d5d6db", Dark: "#1a1b26"},
	contrast:           lipgloss.AdaptiveColor{Light: "#a9b1d6", Dark: "#343b58"},
	backgroundContrast: lipgloss.AdaptiveColor{Light: "#1a1b26", Dark: "#d5d6db"},
}

// DisplayColorSchemes outputs a quick preview of the configured
// color scheme to stdout.
func DisplayColorSchemes() {
	cs := colors
	bold := lipgloss.NewStyle().Bold(true)
	darkBox := lipgloss.NewStyle().Width(lipglossStyleWidth).Background(lipgloss.Color(cs.background.Dark)).Padding(lipglossStylePadding)
	lightBox := lipgloss.NewStyle().Width(lipglossStyleWidth).Background(lipgloss.Color(cs.background.Light)).Padding(lipglossStylePadding)

	log.Infof("ColorScheme test for %s:", bold.Render(cs.name))
	textColors := lipgloss.JoinVertical(lipgloss.Left,
		colorText("highlight", cs.highlight),
		colorText("special", cs.special),
		colorText("critical", cs.critical),
		colorText("high", cs.high),
		colorText("medium", cs.medium),
		"plain text",
	)
	columnsWithBackgrounds := lipgloss.JoinHorizontal(lipgloss.Left,
		lightBox.Render(textColors),
		darkBox.Render(textColors),
	)
	display(columnsWithBackgrounds)

	styles = makeStyles()
	log.Info("Sample matches:")
	for _, match := range getSampleMatches() {
		display(renderMatchPretty(match))
	}
}

func colorText(text string, color lipgloss.AdaptiveColor) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(color).Width(lipglossStyleWidth)
	return style.Render(text)
}

func display(render string) {
	_, err := fmt.Println(render)
	if err != nil {
		log.Fatal("having issues with fmt", "err", err)
	}
}

func getSampleMatches() []*grype.Match {
	return []*grype.Match{
		genMatch("Critical", "CVE-example-example"),
		genMatch("High", "CVE-other-example"),
		genMatch("Medium", "CVE-yet-another-example"),
		genMatch("Low", "CVE-yaml-yaml-example"),
		genMatch("Unknown", "CVE-unknown-example"),
	}
}

func genMatch(severity, id string) *grype.Match {
	return &grype.Match{
		Vulnerability: grype.Vulnerability{
			Severity:    severity,
			ID:          id,
			Description: "example description of a vulnerability",
			Fix:         grype.Fix{State: "fixed"},
		},
		Artifact: grype.Artifact{
			Language:  "go",
			Purl:      "pkg:example/example@4.2.0",
			Locations: []grype.Location{{Path: "example/path"}},
		},
	}
}
