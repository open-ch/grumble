package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/open-ch/grumble/parse"
	"github.com/open-ch/grumble/sarif"
)

// getConvertCommand creates a new cobra command for converting grype reports to sarif format
func getConvertCommand() *cobra.Command {
	var (
		inputPath  string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:     "convert",
		Short:   "Convert a Grype JSON report to SARIF format",
		Long:    "Convert a Grype vulnerability report from JSON format to SARIF (Static Analysis Results Interchange Format) for integration with security tools and CI/CD pipelines.",
		Example: "grumble convert -i grype-report.json -o grype-report.sarif",
		Run: func(_ *cobra.Command, _ []string) {
			if err := convertGrypeToSARIF(inputPath, outputPath); err != nil {
				log.Fatalf("conversion failed: %s", err)
			}
		},
	}

	cmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to the Grype JSON report file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Path for the output SARIF file (defaults to input path with .sarif extension)")

	if err := cmd.MarkFlagRequired("input"); err != nil {
		log.Errorf("could not mark 'input' as required flag: %v", err)
	}

	return cmd
}

// convertGrypeToSARIF handles the conversion logic
func convertGrypeToSARIF(inputPath, outputPath string) error {
	// validate input file exists
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", inputPath)
	}

	// determine output path if not provided
	if outputPath == "" {
		ext := filepath.Ext(inputPath)
		outputPath = strings.TrimSuffix(inputPath, ext) + ".sarif"
	}

	log.Infof("starting conversion: input_file=%s, output_file=%s", inputPath, outputPath)

	// parse grype document
	grypeDoc, err := parse.GrypeFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to parse grype file: %w", err)
	}

	log.Debugf("parsed grype document: matches=%d, ignored_matches=%d",
		len(grypeDoc.Matches),
		len(grypeDoc.IgnoredMatches))

	// convert to sarif
	sarifReport, err := sarif.GrypeToSARIF(grypeDoc)
	if err != nil {
		return fmt.Errorf("failed to convert to SARIF: %w", err)
	}

	// marshal to json with indentation for readability
	sarifJSON, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	// write to output file
	const filePermissions = 0600
	if err := os.WriteFile(outputPath, sarifJSON, filePermissions); err != nil {
		return fmt.Errorf("failed to write SARIF file: %w", err)
	}

	log.Infof("conversion completed successfully: output_file=%s, size_bytes=%d",
		outputPath,
		len(sarifJSON))

	return nil
}
