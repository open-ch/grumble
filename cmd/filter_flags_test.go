package cmd

//revive:disable:unused-parameter

import (
	"errors"
	"testing"

	"github.com/open-ch/grumble/filters"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type testSetCase struct {
	flag       string
	cmdLineArg string
	loadConfig bool
}

type testGetCase struct {
	codeOwners     string
	severity       string
	pathPrefix     string
	fixState       string
	codeOwnersFlag string
	severityFlag   string
	pathPrefixFlag string
	fixStateFlag   string
}

func TestSetFilterValuesForCommand(t *testing.T) {
	var tests = []testSetCase{
		{
			flag:       filters.Codeowners,
			cmdLineArg: "@Open-Systems-SASE/topic-bazel",
		},
		{
			flag: filters.Codeowners,
		},
		{
			flag:       filters.Codeowners,
			cmdLineArg: "@Open-Systems-SASE/topic-bazel",
			loadConfig: true,
		},
		{
			flag:       filters.Severity,
			loadConfig: true,
		},
		{
			flag:       filters.PathPrefix,
			loadConfig: true,
		},
		{
			flag:       filters.FixState,
			cmdLineArg: "fixed",
			loadConfig: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			viper.Reset()
			if tc.loadConfig {
				viper.SetConfigFile("testdata/grumble.config")
				viper.SetConfigType("yaml")
				err := viper.ReadInConfig()
				if err != nil {
					var e viper.ConfigFileNotFoundError
					if errors.As(err, &e) {
						assert.Fail(t, "Failed to parse config %v", e)
					}
				}
			}
			cmd := createTestCommand()
			filtersValues := &filters.Filters{}

			if tc.cmdLineArg != "" {
				err := cmd.Flags().Set(tc.flag, tc.cmdLineArg)
				viperFlag := viper.GetString(tc.flag)
				assert.Equal(t, viperFlag, tc.cmdLineArg)
				if err != nil {
					assert.NoError(t, err)
				}
			}

			setFilterValue(tc.flag, filtersValues)
			assertForFlag(t, tc, filtersValues)
		})
	}
}

func TestGetFilterValuesForCommand(t *testing.T) {
	var tests = []testGetCase{
		{
			codeOwners:     "@Open-Systems-SASE/topic-bazel",
			severity:       "High",
			pathPrefix:     "bazel",
			fixState:       "fixed",
			codeOwnersFlag: "@Open-Systems-SASE/topic-bazel",
			severityFlag:   "High",
			pathPrefixFlag: "bazel",
		},
		{
			codeOwners: "@Open-Systems-SASE/topic-random",
			severity:   "medium",
			pathPrefix: "/topic/bazel",
			fixState:   "fixed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.codeOwners, func(t *testing.T) {
			var err error
			viper.Reset()
			viper.SetConfigFile("testdata/grumble.config")
			viper.SetConfigType("yaml")
			err = viper.ReadInConfig()
			if err != nil {
				var e viper.ConfigFileNotFoundError
				if errors.As(err, &e) {
					assert.Fail(t, "Failed to parse config %v", e)
				}
			}
			cmd := createTestCommand()
			expected := filters.Filters{Severity: tc.severity, Codeowners: tc.codeOwners, PathPrefix: tc.pathPrefix, FixState: tc.fixState}

			if tc.codeOwnersFlag != "" {
				err = cmd.Flags().Set(filters.Codeowners, tc.codeOwnersFlag)
			}
			if tc.severityFlag != "" {
				err = cmd.Flags().Set(filters.Severity, tc.severityFlag)
			}
			if tc.pathPrefixFlag != "" {
				err = cmd.Flags().Set(filters.PathPrefix, tc.pathPrefixFlag)
			}
			if tc.fixStateFlag != "" {
				err = cmd.Flags().Set(filters.FixState, tc.fixStateFlag)
			}
			if err != nil {
				assert.NoError(t, err)
			}

			filtersValues := getFilterValues()
			assert.Equal(t, &expected, filtersValues)
		})
	}
}

func createTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "test command",
		Long:  "test command",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	addAndBindFilterFlags(cmd)
	return cmd
}

func assertForFlag(t *testing.T, tc testSetCase, filtersValues *filters.Filters) {
	t.Helper()
	expected := viper.GetString(tc.flag)
	switch tc.flag {
	case filters.Codeowners:
		assert.Equal(t, filtersValues.Codeowners, expected)
	case filters.Severity:
		assert.Equal(t, filtersValues.Severity, expected)
	case filters.PathPrefix:
		assert.Equal(t, filtersValues.PathPrefix, expected)
	case filters.FixState:
		assert.Equal(t, filtersValues.FixState, expected)
	default:
		assert.Fail(t, "unknown flag")
	}
}
