package cmd

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

func getDemoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "short description",
		Long: `Long description
`,
		Run: func(cmd *cobra.Command, args []string) {
			highlight := lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
			special := lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
			moduleBox := lipgloss.NewStyle().
				Foreground(special).
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(highlight).
				PaddingLeft(4).
				PaddingRight(4)

			_, _ = fmt.Println(moduleBox.Render(`
  ________                   ___.   .__
 /  _____/______ __ __  _____\_ |__ |  |   ____
/   \  __\_  __ \  |  \/     \| __ \|  | _/ __ \
\    \_\  \  | \/  |  /  Y Y  \ \_\ \  |_\  ___/
 \______  /__|  |____/|__|_|  /___  /____/\___  >
        \/                  \/    \/          \/
`))
		},
	}

	return cmd
}
