package cmd

import (
	"github.com/spf13/cobra"

	"github.com/open-ch/grumble/format"
)

func getDevCommands() *cobra.Command {
	devCmd := &cobra.Command{
		Use:    "dev",
		Short:  "these are not the droids you're looking for",
		Hidden: true,
	}

	colorsCmd := &cobra.Command{
		Use:   "colors",
		Short: "helper to check the color schemes",
		Run: func(cmd *cobra.Command, args []string) {
			format.DisplayColorSchemes()
		},
	}

	devCmd.AddCommand(colorsCmd)

	return devCmd
}
