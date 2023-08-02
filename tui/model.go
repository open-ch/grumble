package tui

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/grype"
)

type viewMode int

const (
	viewList viewMode = iota
	viewDetails
)

// matchBrowserModel must implement the bubbletea.Model interface:
// Init(), Update(), View()
// https://github.com/charmbracelet/bubbletea/blob/master/tea.go#L38
type matchBrowserModel struct {
	list          list.Model
	view          viewMode
	details       viewport.Model
	detailsHeader string
}

func buildDocumentBrowserModel(d *grype.Document) matchBrowserModel {
	items := make([]list.Item, len(d.Matches))
	for i, m := range d.Matches {
		items[i] = matchListItem{
			match: m,
		}
	}

	renderDelegate := list.NewDefaultDelegate()
	renderDelegate.ShowDescription = false
	renderDelegate.SetSpacing(0)

	m := matchBrowserModel{
		list:    list.New(items, renderDelegate, 0, 0),
		details: viewport.New(0, 0),
	}
	m.list.DisableQuitKeybindings()
	m.list.Title = "Grumble"
	m.list.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
			key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "open url")),
			key.NewBinding(key.WithKeys("⏎"), key.WithHelp("⏎", "show details")),
			key.NewBinding(key.WithKeys("␛"), key.WithHelp("␛", "hide details")),
		}
	}
	m.list.AdditionalFullHelpKeys = m.list.AdditionalShortHelpKeys

	return m
}

func (matchBrowserModel) Init() tea.Cmd { return nil }

// matchListItem must implement the list.DefaultItem interface when using the defaultDelegate:
// Description(), Title(), FilterValue()
// https://pkg.go.dev/github.com/charmbracelet/bubbles@v0.15.0/list#DefaultItem
type matchListItem struct {
	match *grype.Match
}

// What the defaultDelegate render of list will display for each entry
func (i matchListItem) Title() string { return format.RenderMatchShort(i.match) }

// Description is deplayed as the second line in the list if ShowDescription is enabled
func (i matchListItem) Description() string { return i.match.Vulnerability.Description }

// FilterValue returns the text to search when using fuzzy find
func (i matchListItem) FilterValue() string { return format.RenderMatchShort(i.match) }
