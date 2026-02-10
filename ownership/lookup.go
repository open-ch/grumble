package ownership

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/hmarr/codeowners"
	"github.com/spf13/viper"
)

// Lookup allows looking up against different ownership types, currently only codeowners is supported.
type Lookup struct {
	codeowners codeowners.Ruleset
}

// Default lookup singleton
//
//nolint:gochecknoglobals // not worth refactoring at the moment
var lookup *Lookup

// LoadFromCODEOWNERS builds a new ownership Lookup from a codeowners file.
func LoadFromCODEOWNERS(codeownersPath string) (*Lookup, error) {
	// nosemgrep: go-use-root-open-osag
	file, err := os.Open(codeownersPath)
	if err != nil {
		return nil, err
	}

	ruleset, err := codeowners.ParseFile(file)
	if err != nil {
		return nil, err
	}

	return &Lookup{
		codeowners: ruleset,
	}, nil
}

// SetLookup configures the default lookup singleton
func SetLookup(l *Lookup) {
	lookup = l
}

// LookupFor returns the codeowners for a given path
// rendered as a comma separated string if multiple.
func LookupFor(repoPath string) ([]string, error) {
	if err := initDefaultLookupIfNeeded(); err != nil {
		return []string{}, err
	}
	// path must be relative. Since grype 0.64.0, grype sends a leading '/'
	repoPath = strings.TrimPrefix(repoPath, "/")

	rule, err := lookup.codeowners.Match(repoPath)
	if err != nil {
		return []string{}, err
	}

	if rule == nil {
		return []string{}, nil
	}

	var owners = make([]string, 0)
	for _, owner := range rule.Owners {
		owners = append(owners, owner.String())
	}
	return owners, nil
}

// IsOwnedBy finds out if a path is owned by one of multiple owners
func IsOwnedBy(repoPath string, ownersList []string) (bool, error) {
	// repoPath must be relative. Since grype 0.64.0, they send a leading '/'
	repoPath = strings.TrimPrefix(repoPath, "/")
	if err := initDefaultLookupIfNeeded(); err != nil {
		return false, err
	}

	rule, err := lookup.codeowners.Match(repoPath)
	if err != nil {
		return false, err
	}

	for _, owner := range rule.Owners {
		for _, desiredOwners := range ownersList {
			// maybe lookup.IsOwnedBy(path, arrayOfOwners) instead of ownership.LookupFor
			if owner.String() == desiredOwners {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetCodeowners returns the list of codeowners from the codeowners file
func GetCodeowners() []string {
	codeownersPath := viper.GetString("codeownersPath")
	repositoryPath := viper.GetString("repositoryPath")
	if repositoryPath != "" {
		codeownersPath = path.Join(repositoryPath, codeownersPath)
	}
	cmd := fmt.Sprintf("awk '{print $2}' %s | grep '^@' | sort | uniq", codeownersPath)
	log.Debugf("extracting codeowners with command=%s", cmd)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		log.Error(err)
		return nil
	}
	owners := strings.Split(string(out), "\n")
	log.Debugf("found %d codeowner entries", len(owners))
	return owners
}

func initDefaultLookupIfNeeded() error {
	if lookup != nil {
		return nil
	}

	codeownersPath := viper.GetString("codeownersPath")
	repositoryPath := viper.GetString("repositoryPath")
	if repositoryPath != "" {
		codeownersPath = path.Join(repositoryPath, codeownersPath)
	}
	l, err := LoadFromCODEOWNERS(codeownersPath)
	if err != nil {
		return err
	}
	SetLookup(l)

	return nil
}
