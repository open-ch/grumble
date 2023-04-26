package cmd

import (
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Mapping from flags names to config file names
// to sync between viper and cobra
// - Use flag names as keys
// - Use yaml path (dot separated) as values
//
// For example to map:
//
//	git:
//	  main:
//	    branch: something
//
// to `--git-main-branch=something`:
//
//	"git-main-branch": "git.main.branch",
//
// See syncViperToCommandFlags for implementation details
var configMap = map[string]string{
	// example mapping: "git-main-branch": "git.main.branch",
}

// GetRootCommand returns the root command used to
// run the grumble cli.
func GetRootCommand() *cobra.Command {
	highlight := lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special := lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	moduleBox := lipgloss.NewStyle().
		Foreground(special).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(highlight).
		PaddingLeft(4).
		PaddingRight(4)

	logo := moduleBox.Render(`
  ________                   ___.   .__
 /  _____/______ __ __  _____\_ |__ |  |   ____
/   \  __\_  __ \  |  \/     \| __ \|  | _/ __ \
\    \_\  \  | \/  |  /  Y Y  \ \_\ \  |_\  ___/
 \______  /__|  |____/|__|_|  /___  /____/\___  >
        \/                  \/    \/          \/`)

	rootCmd := &cobra.Command{
		Use:           "grumble",
		Short:         "short description of grumble",
		Long:          logo,
		SilenceErrors: true, // Avoid ugly double print on unknown commands
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Prevent hanging on bootstrap: https://github.com/charmbracelet/lipgloss/issues/73
			lipgloss.SetHasDarkBackground(termenv.HasDarkBackground())
			return initializeConfig(cmd)
		},
	}
	rootCmd.AddCommand(getDevCommands())
	rootCmd.AddCommand(getFetchCommand())
	rootCmd.AddCommand(getParseCommand())

	globalFlags := rootCmd.PersistentFlags()
	globalFlags.String("format", "", "Selects the output format for grumble (*pretty*, json, prometheus, short)")
	globalFlags.String("log-level", "", "Sets logger output level (debug|info|warn|error) (default: info)")
	globalFlags.Bool("debug", false, "Sets logger output level to debug and enables reporter")

	return rootCmd
}

func initializeConfig(cmd *cobra.Command) error {
	viper.SetConfigName("grumble.config")
	viper.SetConfigType("yaml")
	// Note: first match will be used, multiple config files not merged by default
	// (it could be done with additional code if needed)
	//
	// If the working directory is inside a git repo, add repo root to config paths.
	repoRoot, err := getRepositoryRoot()
	if err == nil {
		viper.AddConfigPath(repoRoot)
		viper.AddConfigPath(path.Join(repoRoot, "cicd"))
		viper.Set("repositoryPath", repoRoot)
	} else {
		log.Warn("Unable to locate repository root (grumble assumes the current working directory is part of a git repository)", "err", err)
	}
	viper.AddConfigPath("$HOME/.config/grumble")

	viper.SetDefault("codeownersPath", "CODEOWNERS")
	viper.SetDefault("format", "pretty")
	viper.SetDefault("prometheusMetricName", "your_vulnerability")
	viper.SetDefault("usernameEnvVar", "GRUMBLE_USERNAME")
	viper.SetDefault("passwordEnvVar", "GRUMBLE_PASSWORD")
	viper.SetDefault("log-level", "info")

	err = viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Warnf("Failed to parse config %v\n", err)
		}
	}

	// Bind config to env as well
	viper.BindEnv("fetchUrl")
	// For example usernameEnvVar will read GRUMBLE_PASSWORDENVVAR
	// we don't need viper.MustBindEnv("usernameEnvVar") since we have defaults above
	viper.SetEnvPrefix("GRUMBLE")
	viper.AutomaticEnv()

	syncViperToCommandFlags(cmd)

	log.SetReportTimestamp(false)
	log.SetReportCaller(false)
	if viper.GetBool("debug") {
		log.SetReportCaller(true)
		viper.Set("log-level", "debug")
	}
	switch viper.GetString("log-level") {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.Warnf("Unknown log level: %s (supported levels: debug, info, warn, error)", viper.GetString("log-level"))
	}

	return nil
}

func getRepositoryRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	gitCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	gitCmd.Dir = cwd
	output, err := gitCmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// syncViperToCommandFlags makes paths in yaml config available to
// rootCmd.PersistentFlags() transparently
func syncViperToCommandFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	viper.BindPFlags(flags)
	flags.VisitAll(func(f *pflag.Flag) {
		if entry, ok := configMap[f.Name]; ok && !f.Changed && viper.IsSet(entry) {
			val := viper.GetString(entry)
			_ = cmd.Flags().Set(f.Name, val)
		}
	})
}
