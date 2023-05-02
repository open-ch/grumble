package tui

import (
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/grype"
)

// matchBrowserModel must implement the bubbletea.Model interface:
// Init(), Update(), View()
// https://github.com/charmbracelet/bubbletea/blob/master/tea.go#L38
type matchBrowserModel struct {
	list list.Model
	// TODO track if we're in detail or list view
}

func buildDocumentBrowserModel(d *grype.Document) matchBrowserModel {
	items := make([]list.Item, len(d.Matches))
	for i, match := range d.Matches {
		items[i] = matchListItem{
			match: match,
		}
	}

	renderDelegate := list.NewDefaultDelegate()
	renderDelegate.ShowDescription = false
	renderDelegate.SetSpacing(0)

	m := matchBrowserModel{list: list.New(items, renderDelegate, 0, 0)}
	m.list.Title = "Grumble"
	return m
}

func (matchBrowserModel) Init() tea.Cmd { return nil }

// matchListItem must implement the list.DefaultItem interface when using the defaultDelegate:
// Description(), Title(), FilterValue()
// https://pkg.go.dev/github.com/charmbracelet/bubbles@v0.15.0/list#DefaultItem
type matchListItem struct {
	match grype.Match
}

func (i matchListItem) Title() string       { return format.RenderMatchShort(&i.match) }
func (i matchListItem) Description() string { return i.match.Vulnerability.Description }
func (i matchListItem) FilterValue() string { return format.RenderMatchShort(&i.match) }
