package cmd

import (
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/open-ch/grumble/parse"
	"github.com/open-ch/grumble/tui"
)

func getExploreCommand() *cobra.Command {
	var path string
	exploreCmd := &cobra.Command{
		Use:     "explore",
		Aliases: []string{"xp"},
		Short:   "An experimental interactive grumble",
		Long: `Experimental: Explore allows interactively browsing a document via the terminal

Curently explore works as an alternative to grumble parse and takes the --input flag
to read a document then exposes it in interactive mode.
`,
		Run: func(cmd *cobra.Command, args []string) {
			sweetReport, err := parse.GrypeFile(path)
			if err != nil {
				log.Fatalf("grumble gives up: %s\n", err)
			}
			sortedResults := sweetReport.Sort()
			err = tui.Explore(sortedResults)
			if err != nil {
				log.Fatal("Document exploration encountered an error", "err", err)
			}
		},
	}

	exploreCmd.Flags().StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	exploreCmd.MarkFlagFilename("input")
	exploreCmd.MarkFlagRequired("input")

	return exploreCmd
}
