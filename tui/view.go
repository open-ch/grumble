package tui

import (
	"github.com/charmbracelet/lipgloss"
)

//nolint:gochecknoglobals,mnd // not worth refactoring at the moment
var docStyle = lipgloss.NewStyle().Margin(1, 2)

func (m matchBrowserModel) View() string { //nolint:gocritic
	switch m.view {
	case viewDetails:
		return m.detailsView()
	default:
		return docStyle.Render(m.list.View())
	}
}

func (m matchBrowserModel) detailsView() string { //nolint:gocritic
	return docStyle.Render(lipgloss.JoinVertical(lipgloss.Top,
		m.detailsHeader,
		m.details.View(),
	))
}
