package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/open-ch/grumble/grype"

	"github.com/open-ch/grumble/download"
	"github.com/open-ch/grumble/parse"
	"github.com/open-ch/grumble/tui"
)

func getExploreCommand() *cobra.Command {
	path := ""
	filters := &grype.Filters{}

	exploreCmd := &cobra.Command{
		Use:     "explore",
		Aliases: []string{"x"},
		Short:   "An experimental interactive grumble",
		Long: `Experimental: Explore allows interactively browsing a document via the terminal

Explore works in parse and fetch mode:
- Default: fetch from url in config
- --url: fetch from specified url
- --input: parse local file
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var grypeReport *grype.Document
			var err error

			if path != "" {
				grypeReport, err = parse.GrypeFile(path)
				if err != nil {
					return err
				}
			} else {
				url := viper.GetString("fetchUrl")
				if url == "" {
					return fmt.Errorf("required flag \"url\" (or config value fetchUrl) not set")
				}

				rawReport, err := download.FileFromURL(url)
				if err != nil {
					return fmt.Errorf("grumble could not fetch %s: %w", url, err)
				}
				grypeReport, err = parse.GrypeReport(rawReport)
				if err != nil {
					return err
				}
			}

			filteredResults := grypeReport.Filter(filters)
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
	exploreCmd.MarkFlagFilename("input")

	flags.StringP("url", "u", "", "Url of grype report to fetch")
	viper.BindPFlag("fetchUrl", flags.Lookup("url"))

	addAndBindFilterFlags(exploreCmd, filters)

	exploreCmd.MarkFlagsMutuallyExclusive("input", "url")

	return exploreCmd
}
