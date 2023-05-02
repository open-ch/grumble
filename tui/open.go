package tui

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/charmbracelet/log"

	"github.com/open-ch/grumble/grype"
)

func openMatchBestURL(match *grype.Match) error {
	for _, url := range match.Vulnerability.Urls {
		if strings.HasPrefix(url, "ftp://") {
			log.Debug("Skipping ftp url", "url", url)
			continue
		}
		return openURL(url)
	}
	return fmt.Errorf("error no suitable urls to open for %s", match.Vulnerability.ID)
}

func openURL(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform os: %s", runtime.GOOS)
	}

	return err
}
