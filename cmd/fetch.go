package cmd

import (
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/download"
	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/parse"
)

func getFetchCommand() *cobra.Command {
	output := ""
	filters := &grype.Filters{}

	cmd := &cobra.Command{
		Use: "fetch",
		Aliases: []string{
			"f",
		},
		Short: "fetch a grype file from a url and parse it",
		Long: `Fetch and parse a grype file and display formatted results.

One or more filters can be applied to the matches before the results are formatted.
Most filters allow multiple values separated by commas, e.g. --severity Critical,High
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
			url := viper.GetString("fetchUrl")
			if url == "" {
				log.Fatalf("required flag \"url\" (or config value fetchUrl) not set")
			}

			grypeReport, err := download.FileFromURL(url)
			if err != nil {
				log.Fatalf("grumble could not fetch %s: %s\n", url, err)
			}
			if output != "" {
				err = os.WriteFile(output, grypeReport, 0600)
				if err != nil {
					log.Error("grumble failed to write report to file", "err", err)
				}
			}

			sweetReport, err := parse.GrypeReport(grypeReport)
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

	cmd.Flags().StringVarP(&output, "output", "o", "", "Optional path to save the raw fetched report at (before any filters or formats are applied)")
	cmd.Flags().StringP("url", "u", "", "Url of grype report to fetch")
	err := viper.BindPFlag("fetchUrl", cmd.Flags().Lookup("url"))
	if err != nil {
		log.Errorf("could not BindFlag 'fetchUrl': %v", err)
	}
	addAndBindFilterFlags(cmd, filters)

	return cmd
}
