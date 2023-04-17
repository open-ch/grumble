package cmd

import (
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/format"
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
			outputFormat := viper.GetString("format")
			sweetReport, err := parse.GrypeFile(path)
			if err != nil {
				log.Fatalf("grumble gives up: %s\n", err)
			}

			formatter := format.NewFormatter(outputFormat, os.Stdout)
			err = formatter.Print(sweetReport)
			if err != nil {
				log.Fatalf("grumble cannot output report: %s\n", err)
			}
		},
	}

	cmd.Flags().StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	cmd.MarkFlagRequired("input")
	return cmd
}
