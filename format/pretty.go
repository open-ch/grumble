package format

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"golang.org/x/term"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/ownership"
)

const defaultWidth = 120

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

type summary struct {
	total    int
	critical int
	high     int
	medium   int
	low      int
	fixed    int
	dbAge    time.Time
}

var styles stylesSet

func renderPretty(document *grype.Document) (string, error) {
	styles = makeStyles()
	if len(document.Matches) == 0 {
		return styles.emptyBox.Render(lipgloss.JoinVertical(lipgloss.Left, "No matches in document", getSquirel())), nil
	}

	var matches []string
	summary := &summary{
		dbAge: document.Descriptor.DB.Built,
	}
	for _, match := range document.Matches {
		render := renderMatchPretty(&match)
		matches = append(matches, render)
		summary.add(&match)
	}
	matches = append(matches, renderSummary(summary))

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

func renderSummary(s *summary) string {
	counterStyle := styles.constrast.Copy().PaddingLeft(1).PaddingRight(1)
	total := counterStyle.Render(fmt.Sprintf("total: %d", s.total))
	var critical, high, medium, low, fixed string
	log.Info("summary", "stats", s)
	if s.critical > 0 {
		critical = counterStyle.Copy().Background(colors.critical).
			Render(fmt.Sprintf("crit: %d", s.critical))
	}
	if s.high > 0 {
		high = counterStyle.Copy().Background(colors.high).
			Render(fmt.Sprintf("high: %d", s.high))
	}
	if s.medium > 0 {
		medium = counterStyle.Copy().Background(colors.medium).
			Render(fmt.Sprintf("med: %d", s.medium))
	}
	if s.low > 0 {
		low = counterStyle.Copy().Background(colors.low).
			Render(fmt.Sprintf("low: %d", s.low))
	}
	if s.fixed > 0 {
		fixed = counterStyle.Copy().Background(colors.good).
			Render(fmt.Sprintf("fixes: %d", s.fixed))
	}

	w := lipgloss.Width
	remainingWidth := styles.width - w(styles.logo) - w(total) - w(critical) - w(high) - w(medium) - w(low) - w(fixed)
	log.Info("Width info", "remaining", remainingWidth, "w high", w(high), "w low", w(low), "logo", w(styles.logo), "total", w(total))
	flexibleWidth := styles.constrast.Copy().AlignHorizontal(lipgloss.Right).
		PaddingRight(1).Width(remainingWidth)
	dbInfo := flexibleWidth.Render(fmt.Sprintf("Grype db: %s", s.dbAge.Format(time.DateOnly)))

	return styles.summaryBox.Render(lipgloss.JoinHorizontal(lipgloss.Top,
		styles.logo,
		total,
		critical,
		high,
		medium,
		low,
		fixed,
		dbInfo,
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
		fmt.Sprintf("  → %s", path),
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

	return stylesSet{
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

func (s *summary) add(m *grype.Match) {
	switch m.Vulnerability.Severity {
	case "Critical":
		s.critical++
	case "High":
		s.high++
	case "Medium":
		s.medium++
	case "Low":
		s.low++
	}
	if m.Vulnerability.Fix.State == "fixed" {
		s.fixed++
	}
	s.total++
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
