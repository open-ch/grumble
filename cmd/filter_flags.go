package cmd

import (
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/open-ch/grumble/grype"
)

func addAndBindFilterFlags(cmd *cobra.Command) {
	cmd.Flags().String(grype.FixState, "", "Filter matches based on availability of a fix (unknown, not-fixed, fixed)")
	cmd.Flags().String(grype.PathPrefix, "", "Filter matches based on the artifact path by prefix")
	cmd.Flags().String(grype.Severity, "", "Filter matches based on severity (Critical, High, Medium, Low, Negligible, Unknown severity)")
	cmd.Flags().String(grype.Codeowners, "", `Filter matches based on ownership (supports github CODEOWNERS format)
The CODEOWNERS path can be configured via codeownersPath in the config (default "CODEOWNERS").`)
	// Bind the grumble flags to viper
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		log.Errorf("could not BindFlags: %v", err)
	}
}

// getFilterValues returns the values of the filter flags from the command line or viper config, giving precedence to the command line
func getFilterValues() *grype.Filters {
	filter := &grype.Filters{}
	setFilterValue(grype.FixState, filter)
	setFilterValue(grype.PathPrefix, filter)
	setFilterValue(grype.Severity, filter)
	setFilterValue(grype.Codeowners, filter)
	return filter
}

// setFilterValue is a utility method to set the value of a filter
func setFilterValue(identifier string, filter *grype.Filters) {
	result := viper.GetString(identifier)

	switch identifier {
	case grype.FixState:
		filter.FixState = result
	case grype.PathPrefix:
		filter.PathPrefix = result
	case grype.Severity:
		filter.Severity = result
	case grype.Codeowners:
		filter.Codeowners = result
	default:
		log.Errorf("Could not get filter value for: %v", identifier)
	}
}
