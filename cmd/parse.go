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
	path := ""
	filters := &grype.Filters{}

	cmd := &cobra.Command{
		Use:   "parse",
		Short: "parse a grype output file",
		Long: `Parses a locally available grype file and display formatted results.
This is the same as the fetch option but with a local file.
`,
		Run: func(cmd *cobra.Command, args []string) {
			errorList := filters.Validate()
			if errorList != nil {
				for _, e := range errorList {
					log.Error(e)
				}
				os.Exit(1)
			}
			outputFormat := viper.GetString("format")
			sweetReport, err := parse.GrypeFile(path)
			if err != nil {
				log.Fatal(err)
			}

			log.Debug("Match filters", "filters", filters)
			filteredResults := sweetReport.Filter(filters)
			sortedResults := filteredResults.Sort()

			formatter := format.NewFormatter(outputFormat, os.Stdout)
			err = formatter.Print(sortedResults)
			if err != nil {
				log.Fatalf("grumble cannot output report: %s\n", err)
			}
		},
	}

	cmd.Flags().StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	err := cmd.MarkFlagRequired("input")
	if err != nil {
		log.Errorf("could not mark 'input' as required flag: %v", err)
	}
	addAndBindFilterFlags(cmd, filters)
	return cmd
}
