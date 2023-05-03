package main

import (
	"os"

	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/cmd"
)

func main() {
	log.SetReportTimestamp(false) // Quick default for logger config

	if err := cmd.GetRootCommand().Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
