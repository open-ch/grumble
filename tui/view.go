package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var docStyle = lipgloss.NewStyle().Margin(1, 2)

func (m matchBrowserModel) View() string {
	// TODO handle switching between detail and list views
	return docStyle.Render(m.list.View())
}
