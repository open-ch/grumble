package cmd

import (
	"github.com/open-ch/grumble/filters"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addAndBindFilterFlags(cmd *cobra.Command) {
	cmd.Flags().String(filters.FixState, "", "Filter matches based on availability of a fix (unknown, not-fixed, fixed)")
	cmd.Flags().String(filters.PathPrefix, "", "Filter matches based on the artifact path by prefix")
	cmd.Flags().String(filters.Severity, "", "Filter matches based on severity (Critical, High, Medium, Low, Negligible, Unknown severity)")
	cmd.Flags().String(filters.Codeowners, "", `Filter matches based on ownership (supports github CODEOWNERS format)
The CODEOWNERS path can be configured via codeownersPath in the config (default "CODEOWNERS").`)
	// Bind the grumble flags to viper
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		log.Errorf("could not BindFlags: %v", err)
	}
}

// getFilterValues returns the values of the filter flags from the command line or viper config, giving precedence to the command line
func getFilterValues() *filters.Filters {
	filter := &filters.Filters{}
	setFilterValue(filters.FixState, filter)
	setFilterValue(filters.PathPrefix, filter)
	setFilterValue(filters.Severity, filter)
	setFilterValue(filters.Codeowners, filter)
	return filter
}

// setFilterValue is a utility method to set the value of a filter
func setFilterValue(identifier string, filter *filters.Filters) {
	result := viper.GetString(identifier)

	switch identifier {
	case filters.FixState:
		filter.FixState = result
	case filters.PathPrefix:
		filter.PathPrefix = result
	case filters.Severity:
		filter.Severity = result
	case filters.Codeowners:
		filter.Codeowners = result
	default:
		log.Errorf("Could not get filter value for: %v", identifier)
	}
}
