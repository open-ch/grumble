//nolint:dupl // implements same code as fetch, but is different
package cmd

// revive:disable:unused-parameter
// golangci-lint: nolint dupl

import (
	"os"

	"github.com/open-ch/grumble/filters"
	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/parse"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getParseCommand() *cobra.Command {
	path := ""
	syftType := false

	cmd := &cobra.Command{
		Use:   "parse",
		Short: "parse a grype or syft output file",
		Long: `Parses a locally available grype or syft file and display formatted results.
This is the same as the fetch option but with a local file. Defaults to grype documents
`,
		Run: func(cmd *cobra.Command, args []string) {
			filtersValues := getFilterValues()
			errorList := filters.Validate(filtersValues)
			if errorList != nil {
				for _, e := range errorList {
					log.Error(e)
				}
				os.Exit(1)
			}
			outputFormat := viper.GetString("format")
			//nolint:nestif
			if syftType {
				sweetReport, err := parse.SyftFile(path)
				if err != nil {
					log.Fatal(err)
				}

				log.Debug("Match filters", "filters", filtersValues)
				filteredResults := sweetReport.Filter(filtersValues)
				sortedResults := filteredResults.Sort()

				formatter := format.NewFormatter(outputFormat, os.Stdout)
				err = format.Print(formatter, sortedResults)
				if err != nil {
					log.Fatalf("grumble cannot output report: %s\n", err)
				}
			} else {
				sweetReport, err := parse.GrypeFile(path)
				if err != nil {
					log.Fatal(err)
				}

				log.Debug("Match filters", "filters", filtersValues)
				filteredResults := sweetReport.Filter(filtersValues)
				sortedResults := filteredResults.Sort()

				formatter := format.NewFormatter(outputFormat, os.Stdout)
				err = format.Print(formatter, sortedResults)
				if err != nil {
					log.Fatalf("grumble cannot output report: %s\n", err)
				}
			}
		},
	}

	cmd.Flags().StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	cmd.Flags().BoolVar(&syftType, "syft", false, "Parse a syft file instead of a grype file")
	err := cmd.MarkFlagRequired("input")
	if err != nil {
		log.Errorf("could not mark 'input' as required flag: %v", err)
	}
	addAndBindFilterFlags(cmd)
	return cmd
}
