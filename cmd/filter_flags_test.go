package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"

	"github.com/open-ch/grumble/grype"
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
			flag:       grype.Codeowners,
			cmdLineArg: "@Open-Systems-SASE/topic-bazel",
		},
		{
			flag: grype.Codeowners,
		},
		{
			flag:       grype.Codeowners,
			cmdLineArg: "@Open-Systems-SASE/topic-bazel",
			loadConfig: true,
		},
		{
			flag:       grype.Severity,
			loadConfig: true,
		},
		{
			flag:       grype.PathPrefix,
			loadConfig: true,
		},
		{
			flag:       grype.FixState,
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
					if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
						assert.Fail(t, "Failed to parse config %v", err)
					}
				}
			}
			cmd := createTestCommand()
			filters := &grype.Filters{}

			if tc.cmdLineArg != "" {
				err := cmd.Flags().Set(tc.flag, tc.cmdLineArg)
				viperFlag := viper.GetString(tc.flag)
				assert.Equal(t, viperFlag, tc.cmdLineArg)
				if err != nil {
					assert.NoError(t, err)
				}
			}

			setFilterValue(tc.flag, filters)
			assertForFlag(t, tc, filters)
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
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					assert.Fail(t, "Failed to parse config: %v", err)
				}
			}
			cmd := createTestCommand()
			expected := grype.Filters{Severity: tc.severity, Codeowners: tc.codeOwners, PathPrefix: tc.pathPrefix, FixState: tc.fixState}

			if tc.codeOwnersFlag != "" {
				err = cmd.Flags().Set(grype.Codeowners, tc.codeOwnersFlag)
			}
			if tc.severityFlag != "" {
				err = cmd.Flags().Set(grype.Severity, tc.severityFlag)
			}
			if tc.pathPrefixFlag != "" {
				err = cmd.Flags().Set(grype.PathPrefix, tc.pathPrefixFlag)
			}
			if tc.fixStateFlag != "" {
				err = cmd.Flags().Set(grype.FixState, tc.fixStateFlag)
			}
			if err != nil {
				assert.NoError(t, err)
			}

			filters := getFilterValues()
			assert.Equal(t, &expected, filters)
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

func assertForFlag(t *testing.T, tc testSetCase, filters *grype.Filters) {
	t.Helper()
	expected := viper.GetString(tc.flag)
	switch tc.flag {
	case grype.Codeowners:
		assert.Equal(t, filters.Codeowners, expected)
	case grype.Severity:
		assert.Equal(t, filters.Severity, expected)
	case grype.PathPrefix:
		assert.Equal(t, filters.PathPrefix, expected)
	case grype.FixState:
		assert.Equal(t, filters.FixState, expected)
	default:
		assert.Fail(t, "unknown flag")
	}
}
