package format

import (
	"fmt"
	"github.com/charmbracelet/log"

	"github.com/charmbracelet/lipgloss"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/ownership"
)

type stylesSet struct {
	// Text styles
	bold          lipgloss.Style
	faint         lipgloss.Style
	paragraph     lipgloss.Style
	codeowners    lipgloss.Style
	cve           lipgloss.Style
	stateFixed    lipgloss.Style
	stateNotFixed lipgloss.Style
	stateOther    lipgloss.Style

	// Severities
	severityCritical lipgloss.Style
	severityHigh     lipgloss.Style
	severityMedium   lipgloss.Style
	severityLow      lipgloss.Style
	severityOther    lipgloss.Style

	// Box styles
	emptyBox  lipgloss.Style
	matchBox  lipgloss.Style
	reportBox lipgloss.Style
}

var styles stylesSet

func renderPretty(document *grype.Document) (string, error) {
	styles = makeStyles()
	if len(document.Matches) == 0 {
		return styles.emptyBox.Render(lipgloss.JoinVertical(lipgloss.Left, "No matches in document", getSquirel())), nil
	}

	var matches []string
	for _, match := range document.Matches {
		render := renderMatchPretty(&match)
		matches = append(matches, render)
	}

	return styles.reportBox.Render(lipgloss.JoinVertical(lipgloss.Left,
		matches...,
	)), nil
}

func renderMatchPretty(match *grype.Match) string {
	return styles.matchBox.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			renderMatchHeader(match),
			renderMatchDetails(match),
		))
}

func renderMatchHeader(match *grype.Match) string {
	cve := match.Vulnerability.ID
	if len(match.Artifact.Locations) != 1 {
		log.Fatal("unexpected input data, only 1 location supported", "locations", len(match.Artifact.Locations))
	}
	apaths := match.Artifact.Locations[0].Path
	codeowners, err := ownership.LookupFor(apaths)
	if err != nil {
		codeowners = fmt.Sprintf("Error looking up code owners: %s", err)
	}

	return lipgloss.JoinHorizontal(lipgloss.Top,
		renderSeverity(match.Vulnerability.Severity),
		styles.codeowners.Render(codeowners),
		fmt.Sprintf("%s ", match.Artifact.Purl),
		styles.cve.Render(cve),
	)
}

func renderMatchDetails(match *grype.Match) string {
	if len(match.Artifact.Locations) != 1 {
		log.Fatal("unexpected input data, only 1 location supported", "locations", len(match.Artifact.Locations))
	}
	path := match.Artifact.Locations[0].Path

	details := []string{
		styles.paragraph.Render(match.Vulnerability.Description),
	}

	for _, url := range match.Vulnerability.Urls {
		details = append(details, styles.paragraph.Render(url))
	}

	details = append(details,
		renderFixState(match.Vulnerability.Fix.State),
		styles.paragraph.Render("Language:", match.Artifact.Language),
		fmt.Sprintf("→ %s", path),
	)

	return lipgloss.JoinVertical(lipgloss.Left, details...)
}

func renderSeverity(severity string) string {
	switch severity {
	case "Critical":
		return styles.severityCritical.Render(severity)
	case "High":
		return styles.severityHigh.Render(severity)
	case "Medium":
		return styles.severityMedium.Render(severity)
	case "Low":
		return styles.severityLow.Render(severity)
	default:
		return styles.severityOther.Render(severity)
	}
}

func renderFixState(fixState string) string {
	switch fixState {
	case "fixed":
		return styles.stateFixed.Render("✓ Fix available")
	case "not-fixed":
		return styles.stateNotFixed.Render("✗") + styles.faint.Render("Fix not yet available")
	default:
		return styles.stateOther.Render("▴") + styles.faint.Render("Fix state:", fixState)
	}
}

// Create new styles with the current theme
func makeStyles() stylesSet {
	width := 120
	leftIndent := 2
	headerRightPadding := 1

	bold := lipgloss.NewStyle().Bold(true)
	faint := lipgloss.NewStyle().Faint(true)
	header := bold.Copy().PaddingRight(headerRightPadding)
	severity := header.Copy().Width(9) // Critical is the longest one, fix the length
	fix := header.Copy().PaddingLeft(leftIndent).Foreground(colors.neutral)

	return stylesSet{
		bold:             bold,
		faint:            faint,
		paragraph:        faint.Copy().PaddingLeft(leftIndent).Width(width),
		codeowners:       header,
		cve:              faint.Copy().Foreground(colors.contrast).Background(colors.backgroundContrast).PaddingLeft(1).PaddingRight(1),
		stateFixed:       fix.Copy().Foreground(colors.good),
		stateNotFixed:    fix,
		stateOther:       fix,
		severityCritical: severity.Copy().Foreground(colors.critical),
		severityHigh:     severity.Copy().Foreground(colors.high),
		severityMedium:   severity.Copy().Foreground(colors.medium),
		severityLow:      severity.Copy().Foreground(colors.low),
		severityOther:    severity,

		emptyBox: lipgloss.NewStyle().
			Foreground(colors.special).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colors.highlight).
			PaddingLeft(4).
			PaddingRight(4),
		matchBox: lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Width(width), // TODO look up current session with dynamically
		reportBox: lipgloss.NewStyle(),
	}
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
