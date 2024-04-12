package cmd

//revive:disable:unused-parameter cmd parameters are used in the cobra command

import (
	"github.com/open-ch/grumble/format"

	"github.com/spf13/cobra"
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
