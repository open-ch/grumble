package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/open-ch/grumble/grype"
)

// Explore takes a grype document an allows interactively exploring it on a terminal
func Explore(d *grype.Document) error {
	m := buildDocumentBrowserModel(d)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
