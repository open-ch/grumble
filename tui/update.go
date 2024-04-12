package tui

// revive:disable:modifies-value-receiver The bubbletea Model interface doesn't let us work with pointers
// revive:disable:unchecked-type-assertion
// revive:disable:cyclomatic
// golangci-lint: nolint gocritic forcetypeassert (no pointers with bubbletea)

import (
	"encoding/json"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

//nolint:cyclop
func (m matchBrowserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) { //nolint:gocritic,gocyclo
	switch msg := msg.(type) {
	case tea.KeyMsg:
		keyPress := msg.String()
		switch keyPress {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "o":
			if m.list.SelectedItem() != nil && m.list.FilterState() != list.Filtering {
				selectedItem, ok := m.list.SelectedItem().(matchListItem)
				if !ok {
					log.Errorf("Unable to cast selectedItem to matchListItem: %T", m.list.SelectedItem())
					break
				}
				err := openMatchBestURL(selectedItem.match)
				if err != nil {
					log.Warn("Unable to open Match url", "err", err)
				}
			}

		case "enter":
			if m.list.SelectedItem() != nil && m.list.FilterState() != list.Filtering {
				selectedItem, ok := m.list.SelectedItem().(matchListItem)
				if !ok {
					log.Errorf("Unable to cast selectedItem to matchListItem: %T", m.list.SelectedItem())
					break
				}

				rawJSON, err := json.MarshalIndent(selectedItem.match, "", "    ")
				if err != nil {
					m.details.SetContent(err.Error())
				}
				m.view = viewDetails
				// For now we use json as the detail view, later we might define a pretty format
				// for all or most fields.
				m.details.SetContent(string(rawJSON))
				m.detailsHeader = selectedItem.Title()
			}

		case "esc":
			m.view = viewList
		}

	case tea.WindowSizeMsg:
		horizontalMargin, verticalMargin := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-horizontalMargin, msg.Height-verticalMargin)
		m.details.Width = msg.Width - horizontalMargin
		m.details.Height = msg.Height - verticalMargin - lipgloss.Height(m.detailsHeader)
	}

	var cmd tea.Cmd
	if m.view == viewList {
		m.list, cmd = m.list.Update(msg)
	} else if m.view == viewDetails {
		m.details, cmd = m.details.Update(msg)
	}
	return m, cmd
}
