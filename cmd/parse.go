package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/open-ch/grumble/parse"
)

func getParseCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "parse a grype output file",
		Long: `Parses a locally available grype file and display the results
This is the same as the fetch option but with a local file.
`,
		Run: func(cmd *cobra.Command, args []string) {
			sweetReport, err := parse.GrypeFile(path)
			if err != nil {
				log.Fatalf("grumble gives up: %s\n", err)
			}
			_, err = fmt.Println(sweetReport)
			if err != nil {
				log.Fatalf("fmt crumbled under it's own weight, grumble knows not what to do about it: %s\n", err)
			}
		},
	}

	cmd.Flags().StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	cmd.MarkFlagRequired("input")
	return cmd
}
