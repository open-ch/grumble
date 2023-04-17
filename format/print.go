package format

import (
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"

	"github.com/open-ch/grumble/parse"
)

type Formatter struct {
	format string
	writer io.Writer
}

func NewFormatter(format string, writer io.Writer) *Formatter {
	f := &Formatter{
		format,
		writer,
	}
	return f
}

func (f *Formatter) Print(document *parse.GrypeDocument) error {
	var renderFunction func(document *parse.GrypeDocument) (string, error)
	switch f.format {
	default:
		return fmt.Errorf("Invalid formatter print format configured: %s", f.format)
	case "json":
		renderFunction = renderJSON
	case "pretty":
		renderFunction = renderPretty
	}

	output, err := renderFunction(document)
	if err != nil {
		return err
	}

	_, err = io.WriteString(f.writer, fmt.Sprintf("%s\n", output))
	if err != nil {
		return err
	}
	return nil
}

func renderJSON(document *parse.GrypeDocument) (string, error) {
	return document.GetJSON()
}

func renderPretty(document *parse.GrypeDocument) (string, error) {
	width := 120 // TODO look up current session with
	highlight := lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special := lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	emptyBox := lipgloss.NewStyle().
		Foreground(special).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(highlight).
		PaddingLeft(4).
		PaddingRight(4)

	// TODO define colors for the different levels of vunlnerabilities?
	plainStyle := lipgloss.NewStyle().Faint(true)
	purlStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#B9BFCA")).PaddingRight(1)
	sevStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("178")).PaddingRight(1).
		Width(9) // Critical is the longest one
	matchBox := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		Width(width)
	reportBox := lipgloss.NewStyle()

	if len(document.Matches) == 0 {
		return emptyBox.Render(lipgloss.JoinVertical(lipgloss.Left,
			"No matches in document",
			getSquirel(),
		)), nil
	}

	var matches []string
	// TODO extract Matches to a separate struct so we can easily parse it
	// with a separate function
	for _, modulePath := range document.Matches {
		vid := modulePath.Vulnerability.ID
		severity := modulePath.Vulnerability.Severity
		description := modulePath.Vulnerability.Description
		aname := modulePath.Artifact.Purl
		// TODO join all locations into 1 string, + handle 0 if there could be more than 1?
		apaths := modulePath.Artifact.Locations[0].Path
		// We could lookup the code owner based on the path here to output it
		render := matchBox.Render(
			lipgloss.JoinVertical(lipgloss.Left,
				lipgloss.JoinHorizontal(lipgloss.Top,
					sevStyle.Render(severity),
					purlStyle.Render(aname),
					plainStyle.Render(vid),
				),
				plainStyle.Render(description),
				plainStyle.Render(fmt.Sprintf("Path: %s", apaths)),
			))
		matches = append(matches, render)
	}
	return reportBox.Render(lipgloss.JoinVertical(lipgloss.Left,
		matches...,
	)), nil
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
