package cmd

import (
	"github.com/spf13/cobra"

	"github.com/open-ch/grumble/grype"
)

func addAndBindFilterFlags(cmd *cobra.Command, filters *grype.Filters) {
	cmd.Flags().StringVar(&filters.FixState, "fix-state", "", "Filter matches based on availability of a fix (unknown, not-fixed, fixed)")
	cmd.Flags().StringVar(&filters.PathPrefix, "path-prefix", "", "Filter matches based on the artifact path by prefix")
	cmd.Flags().StringVar(&filters.Severity, "severity", "", "Filter matches based on severity (Critical, High, Medium, Low, Negligible, Unknown severity)")
	cmd.Flags().StringVar(&filters.Codeowners, "codeowners", "", `Filter matches based on ownership (supports github CODEOWNERS format)
The CODEOWNERS path can be configured via codeownersPath in the config (default "CODEOWNERS").`)
}
