package cmd

//revive:disable:unused-parameter cmd parameters are used in the cobra command

import (
	"fmt"
	"os"

	"github.com/open-ch/grumble/download"
	"github.com/open-ch/grumble/filters"
	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/parse"
	"github.com/open-ch/grumble/tui"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

//nolint:cyclop
func getExploreCommand() *cobra.Command {
	path := ""
	syftType := false

	exploreCmd := &cobra.Command{
		Use:     "explore",
		Aliases: []string{"x"},
		Short:   "An experimental interactive grumble",
		Long: `Experimental: Explore allows interactively browsing a document via the terminal

Explore works in parse and fetch mode:
- Default: fetch from url in config
- --url: fetch from specified url
- --input: parse local file
- --syft: the input file is a syft file
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var grypeReport *grype.Document
			var err error

			filtersValues := getFilterValues()
			errorList := filters.Validate(filtersValues)
			if errorList != nil {
				for _, e := range errorList {
					log.Error(e)
				}
				os.Exit(1)
			}

			//nolint:nestif
			if path != "" {
				grypeReport, err = parse.GrypeFile(path)
				if err != nil {
					return err
				}
			} else {
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

				rawReport, err2 := download.FileFromURL(url)
				if err2 != nil {
					return fmt.Errorf("grumble could not fetch %s: %w", url, err2)
				}
				grypeReport, err2 = parse.GrypeReport(rawReport)
				if err2 != nil {
					return err2
				}
			}

			filteredResults := grypeReport.Filter(filtersValues)
			sortedResults := filteredResults.Sort()
			err = tui.Explore(sortedResults)
			if err != nil {
				return fmt.Errorf("document exploration encountered an error: %w", err)
			}

			return nil
		},
	}

	flags := exploreCmd.Flags()

	flags.StringVarP(&path, "input", "i", "", "Path of grype file to parse")
	err := exploreCmd.MarkFlagFilename("input")
	if err != nil {
		log.Errorf("could not MarkFlagFilename 'input': %v", err)
	}

	flags.BoolVar(&syftType, "syft", false, "Parse a syft file instead of a grype file")
	flags.StringP("url", "u", "", "Url of grype report to fetch")
	err = viper.BindPFlag("grypeFetchUrl", flags.Lookup("url"))
	if err != nil {
		log.Errorf("could not BindFlag 'grypeFetchUrl': %v", err)
	}
	err = viper.BindPFlag("syftFetchUrl", flags.Lookup("url"))
	if err != nil {
		log.Errorf("could not BindFlag 'syftFetchUrl': %v", err)
	}

	addAndBindFilterFlags(exploreCmd)

	exploreCmd.MarkFlagsMutuallyExclusive("input", "url")

	return exploreCmd
}
