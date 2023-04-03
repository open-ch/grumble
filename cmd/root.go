package cmd

import (
	"log"

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
	rootCmd := &cobra.Command{
		Use:   "grumble",
		Short: "short description of grumble",
		Long: `Long description of grumble
  ________                   ___.   .__
 /  _____/______ __ __  _____\_ |__ |  |   ____
/   \  __\_  __ \  |  \/     \| __ \|  | _/ __ \
\    \_\  \  | \/  |  /  Y Y  \ \_\ \  |_\  ___/
 \______  /__|  |____/|__|_|  /___  /____/\___  >
        \/                  \/    \/          \/
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd)
		},
	}
	rootCmd.AddCommand(getDemoCommand())
	rootCmd.AddCommand(getParseCommand())

	return rootCmd
}

func initializeConfig(cmd *cobra.Command) error {
	viper.SetConfigName(".grumble.config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/configs")
	viper.AddConfigPath("$HOME/.config/myprogram")

	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Failed to parse config %v\n", err)
		}
	}

	syncViperToCommandFlags(cmd)

	return nil
}

// syncViperToCommandFlags makes paths in yaml config available to
// rootCmd.PersistentFlags() transparently
func syncViperToCommandFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if entry, ok := configMap[f.Name]; ok && !f.Changed && viper.IsSet(entry) {
			val := viper.GetString(entry)
			_ = cmd.Flags().Set(f.Name, val)
		}
	})
}
