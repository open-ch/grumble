package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/format"
	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/parse"
)

func getDiffCommand() *cobra.Command {
	before := ""
	after := ""
	filters := &grype.Filters{}

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "diff between 2 grype reports",
		Long: `diff takes two reports and returns the differences in vulnerabilities between them.
This includes added and removed vulnerabilities, other elements of the report are not compared or included.
Both reports must be local files. Also the default format for this command is json.`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			diffFormat, err := cmd.Flags().GetString("format")
			log.Debug("local format flag", "diffFormat", diffFormat)
			if err != nil {
				log.Debug("error reading local format flag using json as default", "err", err)
				diffFormat = "json"
			}
			viper.Set("format", diffFormat)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			errorList := filters.Validate()
			if errorList != nil {
				for _, e := range errorList {
					log.Error(e)
				}
				os.Exit(1)
			}
			outputFormat := viper.GetString("format")
			log.Debug("Flags", "filters", filters, "format", outputFormat)
			beforeReport, err := loadAndFilterReport(before, filters)
			if err != nil {
				return fmt.Errorf("failed to load the before file: %w", err)
			}
			afterReport, err := loadAndFilterReport(after, filters)
			if err != nil {
				return fmt.Errorf("failed to load the after file: %w", err)
			}

			diff := grype.Diff(beforeReport, afterReport)
			log.Infof("Diff: %d added, %d removed", len(diff.Added), len(diff.Removed))

			formatter := format.NewFormatter(outputFormat, os.Stdout)
			err = formatter.PrintDiff(diff)
			if err != nil {
				return fmt.Errorf("failed to format diff: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&before, "before", "", "Path of grype file before")
	err := cmd.MarkFlagRequired("before")
	if err != nil {
		log.Errorf("could not MarkFlagRequired: %v", err)
	}
	cmd.Flags().StringVar(&after, "after", "", "Path of grype file after")
	err = cmd.MarkFlagRequired("after")
	if err != nil {
		log.Errorf("could not MarkFlagRequired: %v", err)
	}
	// Note we override the global flag here because we only want to support 2 formats:
	cmd.Flags().String("format", "json", "Selects the output format for diff (*json*, prometheus)")
	addAndBindFilterFlags(cmd, filters)
	return cmd
}

func loadAndFilterReport(path string, filters *grype.Filters) (*grype.Document, error) {
	report, err := parse.GrypeFile(path)
	if err != nil {
		return nil, err
	}
	filteredReport := report.Filter(filters)
	return filteredReport, nil
}
