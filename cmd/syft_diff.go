package cmd

import (
	"fmt"
	"github.com/open-ch/grumble/parse"
	"github.com/open-ch/grumble/syft"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

func getSyftDiffCommand() *cobra.Command {
	before := ""
	after := ""
	addedSbom := ""
	removedSbom := ""

	cmd := &cobra.Command{
		Use:   "syft-diff",
		Short: "diff between 2 syft reports",
		Long: `syft-diff takes two syft sboms and returns the number of added or removed packages.
Optionally, the two new sboms containing the added or removed packages can be written on disk
Both reports must be local files. Currently, only json is supported as a format`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			beforeReport, err := loadSyftSBOM(before)
			if err != nil {
				return fmt.Errorf("failed to load the before file: %w", err)
			}
			afterReport, err := loadSyftSBOM(after)
			if err != nil {
				return fmt.Errorf("failed to load the after file: %w", err)
			}

			added, removed := syft.Diff(beforeReport, afterReport)
			log.Infof("Diff: %d artifacts added, %d artifacts removed", len(added.Artifacts), len(removed.Artifacts))

			if addedSbom != "" {
				err = parse.WriteSyftFile(added, addedSbom)
				if err != nil {
					return fmt.Errorf("failed to write the sbom with additions: %w", err)
				}
			}

			if removedSbom != "" {
				err = parse.WriteSyftFile(removed, removedSbom)
				if err != nil {
					return fmt.Errorf("failed to write the sbom with removals: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&before, "before", "", "Path of the previous syft SBOM")
	err := cmd.MarkFlagRequired("before")
	if err != nil {
		log.Errorf("could not MarkFlagRequired: %v", err)
	}
	cmd.Flags().StringVar(&after, "after", "", "Path of the new syft SBOM")
	err = cmd.MarkFlagRequired("after")
	if err != nil {
		log.Errorf("could not MarkFlagRequired: %v", err)
	}

	cmd.Flags().StringVar(&addedSbom, "added", "", "Name of the added artifacts SBOM to write to disk")
	cmd.Flags().StringVar(&removedSbom, "removed", "", "Name of the removed artifacts SBOM to write to disk")
	return cmd
}

func loadSyftSBOM(path string) (*syft.Document, error) {
	report, err := parse.SyftFile(path)
	if err != nil {
		return nil, err
	}
	return report, nil
}
