package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/log"
)

func (m matchBrowserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	selectedItem := m.list.SelectedItem().(matchListItem)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		keyPress := msg.String()
		switch keyPress {
		case "ctrl+c":
			return m, tea.Quit
		case "o":
			err := openMatchBestURL(&selectedItem.match)
			if err != nil {
				log.Warn("Unable to open Match url", "err", err)
			}
		case "enter":
			// TODO only if not detail view
			// TODO handle opening the details view (and closing it)
			log.Debug("Display detail view", selectedItem)
		}
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}

	var cmd tea.Cmd
	newListModel, cmd := m.list.Update(msg)
	return matchBrowserModel{list: newListModel}, cmd
}
