package cmd

import (
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

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
Both reports must be local files.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Debug("Active filters", "filters", filters)
			beforeReport, err := loadAndFilterReport(before, filters)
			if err != nil {
				return fmt.Errorf("Failed to load the before file: %w", err)
			}
			afterReport, err := loadAndFilterReport(after, filters)
			if err != nil {
				return fmt.Errorf("Failed to load the after file: %w", err)
			}

			diff := grype.Diff(beforeReport, afterReport)
			json, err := diff.GetJSON()
			if err != nil {
				return fmt.Errorf("Failed to format diff: %w", err)
			}

			log.Infof("Diff: %d added, %d removed", len(diff.Added), len(diff.Removed))
			fmt.Println(json)
			return nil
		},
	}

	cmd.Flags().StringVar(&before, "before", "", "Path of grype file before")
	cmd.MarkFlagRequired("before")
	cmd.MarkPersistentFlagFilename("before", ".json")
	cmd.Flags().StringVar(&after, "after", "", "Path of grype file after")
	cmd.MarkFlagRequired("after")
	cmd.MarkPersistentFlagFilename("after", ".json")
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
