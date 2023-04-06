package cmd

import (
	"github.com/spf13/viper"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/open-ch/grumble/download"
	"github.com/open-ch/grumble/parse"
)

func getFetchCommand() *cobra.Command {
	var url string
	var output string

	cmd := &cobra.Command{
		Use: "fetch",
		Aliases: []string{
			"f",
		},
		Short: "fetch a grype file from a url and parse it",
		Long:  "Fetch and parse a grype file and display the results",
		Run: func(cmd *cobra.Command, args []string) {
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
			_, err = fmt.Println(sweetReport)
			if err != nil {
				log.Fatalf("fmt crumbled under it's own weight, grumble knows not what to do about it: %s\n", err)
			}
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Url of grype report to fetch")
	cmd.Flags().StringVarP(&url, "url", "u", "", "Url of grype report to fetch")
	viper.BindPFlag("fetchUrl", cmd.Flags().Lookup("url"))
	return cmd
}
