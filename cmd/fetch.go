//nolint:dupl // implements same code as parse, but is different
package cmd

// revive:disable:unused-parameter cmd parameters are used in the cobra command
// golangci-lint: nolint cyclop

import (
	"os"

	"github.com/open-ch/grumble/download"
	"github.com/open-ch/grumble/filters"
	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/parse"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//nolint:gocyclo,gocognit,cyclop
//revive:disable:cyclomatic
func getFetchCommand() *cobra.Command {
	output := ""
	syftType := false

	cmd := &cobra.Command{
		Use: "fetch",
		Aliases: []string{
			"f",
		},
		Short: "fetch a grype or syft file from a url and parse it",
		Long: `Fetch and parse a grype or syft file and display formatted results.

One or more filters can be applied to the matches before the results are formatted.
Most filters allow multiple values separated by commas, e.g. --severity Critical,High
Defaults to grype files
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

			var url string
			if syftType {
				url = viper.GetString("syftFetchUrl")
				if url == "" {
					log.Fatalf("required flag \"url\" (or config value syftFetchUrl) not set")
				}
			} else {
				url = viper.GetString("grypeFetchUrl")
				if url == "" {
					log.Fatalf("required flag \"url\" (or config value grypeFetchUrl) not set")
				}
			}
			report, err := download.FileFromURL(url)
			if err != nil {
				log.Fatalf("grumble could not fetch %s: %s\n", url, err)
			}
			if output != "" {
				const permissions os.FileMode = 0600
				err = os.WriteFile(output, report, permissions)
				if err != nil {
					log.Error("grumble failed to write report to file", "err", err)
				}
			}
			//nolint:nestif
			if syftType {
				sweetReport, err := parse.SyftSBOM(report)
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
				sweetReport, err := parse.GrypeReport(report)
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

	cmd.Flags().StringVarP(&output, "output", "o", "", "Optional path to save the raw fetched report at (before any filters or formats are applied)")
	cmd.Flags().StringP("url", "u", "", "Url of the report to fetch")
	cmd.Flags().BoolVar(&syftType, "syft", false, "Parse a syft file instead of a grype file")
	err := viper.BindPFlag("grypeFetchUrl", cmd.Flags().Lookup("url"))
	if err != nil {
		log.Errorf("could not BindFlag 'grypeFetchUrl': %v", err)
	}
	err = viper.BindPFlag("syftFetchUrl", cmd.Flags().Lookup("url"))
	if err != nil {
		log.Errorf("could not BindFlag 'syftFetchUrl': %v", err)
	}
	addAndBindFilterFlags(cmd)

	return cmd
}
