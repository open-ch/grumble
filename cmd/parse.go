package cmd

import (
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/parse"
)

func getParseCommand() *cobra.Command {
	var path string
	var filters grype.Filters

	cmd := &cobra.Command{
		Use:   "parse",
		Short: "parse a grype output file",
		Long: `Parses a locally available grype file and display formatted results.
This is the same as the fetch option but with a local file.
`,
		Run: func(cmd *cobra.Command, args []string) {
			outputFormat := viper.GetString("format")
			sweetReport, err := parse.GrypeFile(path)
			if err != nil {
				log.Fatalf("grumble gives up: %s\n", err)
			}

			log.Debug("Match filters", "filters", filters)
			filteredResults := sweetReport.Filter(&filters)

			formatter := format.NewFormatter(outputFormat, os.Stdout)
			err = formatter.Print(filteredResults)
			if err != nil {
				log.Fatalf("grumble cannot output report: %s\n", err)
			}
		},
	}

	cmd.Flags().StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	cmd.MarkFlagRequired("input")
	cmd.Flags().StringVar(&filters.FixState, "fix-state", "", "Filter matches based on availability of a fix (unknown, not-fixed, fixed)")
	cmd.Flags().StringVar(&filters.PathPrefix, "path-prefix", "", `Filter matches based on the artifact path by prefix`)
	cmd.Flags().StringVar(&filters.Severity, "severity", "", "Filter matches based severity (Critical, High, Medium, Low, Negligible, Unknown severity)")
	return cmd
}
