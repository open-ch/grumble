package format

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"golang.org/x/term"
)

const defaultWidth = 120

var styles *stylesSet

type stylesSet struct {
	// Text styles
	bold          lipgloss.Style
	codeowners    lipgloss.Style
	constrast     lipgloss.Style
	cve           lipgloss.Style
	faint         lipgloss.Style
	paragraph     lipgloss.Style
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
	emptyBox   lipgloss.Style
	summaryBox lipgloss.Style
	matchBox   lipgloss.Style
	reportBox  lipgloss.Style

	// Pre-rendered styles & constants
	logo  string
	width int
}

func initStyles() {
	if styles == nil {
		styles = makeStyles()
	}
}

// makeStyles creates a new styleset with the current theme
func makeStyles() *stylesSet {
	width := getTerminalSessionWidth()
	leftIndent := 2
	headerRightPadding := 1

	bold := lipgloss.NewStyle().Bold(true)
	faint := lipgloss.NewStyle().Faint(true)
	constrast := lipgloss.NewStyle().Foreground(colors.contrast).Background(colors.backgroundContrast)
	header := bold.Copy().PaddingRight(headerRightPadding)
	severity := header.Copy().Width(9) // Critical is the longest one, fix the length
	fix := header.Copy().PaddingLeft(leftIndent).Foreground(colors.neutral)
	logo := bold.Copy().Foreground(colors.special).Background(colors.highlight).
		PaddingLeft(1).PaddingRight(1).SetString("Grumble").String()

	return &stylesSet{
		bold:             bold,
		codeowners:       header,
		constrast:        constrast,
		cve:              constrast.Copy().PaddingLeft(1).PaddingRight(1),
		faint:            faint,
		paragraph:        faint.Copy().PaddingLeft(leftIndent).Width(width),
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
		summaryBox: constrast.MaxHeight(1).Width(width),
		matchBox: lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Width(width),
		reportBox: lipgloss.NewStyle(),

		logo:  logo,
		width: width,
	}
}

func getTerminalSessionWidth() int {
	if !term.IsTerminal(0) {
		log.Warn("Pretty printing on non terminal, usign default width")
		return defaultWidth
	}
	width, _, err := term.GetSize(0)
	if err != nil {
		log.Warn("Failed to lookup terminal width", "err", err)
		return defaultWidth
	}
	return width
}
