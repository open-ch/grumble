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
	var output string
	var url string
	var filters grype.Filters

	cmd := &cobra.Command{
		Use: "fetch",
		Aliases: []string{
			"f",
		},
		Short: "fetch a grype file from a url and parse it",
		Long:  "Fetch and parse a grype file and display the results",
		Run: func(cmd *cobra.Command, args []string) {
			outputFormat := viper.GetString("format")
			url := viper.GetString("fetchUrl")
			if url == "" {
				log.Fatalf("required flag \"url\" (or config value fetchUrl) not set")
			}

			grypeReport, err := download.FileFromURL(viper.GetString("fetchUrl"))
			if err != nil {
				log.Fatalf("grumble could not fetch %s: %s\n", url, err)
			}
			if output != "" {
				err = os.WriteFile(output, grypeReport, 0600)
				if err != nil {
					log.Fatalf("grumble failed to write report to file: %s\n", err)
				}
			}

			sweetReport, err := parse.GrypeReport(grypeReport)
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

	cmd.Flags().StringVarP(&output, "output", "o", "", "Optional path to save the raw fetched report at (before any filters or formats are applied)")
	cmd.Flags().StringVarP(&url, "url", "u", "", "Url of grype report to fetch")
	viper.BindPFlag("fetchUrl", cmd.Flags().Lookup("url"))
	cmd.Flags().StringVar(&filters.FixState, "fix-state", "", "Filter matches based on availability of a fix (unknown, not-fixed, fixed)")
	cmd.Flags().StringVar(&filters.PathPrefix, "path-prefix", "", `Filter matches based on the artifact path by prefix`)
	cmd.Flags().StringVar(&filters.Severity, "severity", "", "Filter matches based severity (Critical, High, Medium, Low, Negligible, Unknown severity)")
	return cmd
}
