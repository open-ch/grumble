package ownership

import (
	"os"
	"path"
	"strings"

	"github.com/hmarr/codeowners"
	"github.com/spf13/viper"
)

// Lookup allows looking up against different ownership types, currently only codeowners is supported.
type Lookup struct {
	codeowners codeowners.Ruleset
}

// Default lookup singleton
var lookup *Lookup

// LoadFromCODEOWNERS builds a new ownership Lookup from a codeowners file.
func LoadFromCODEOWNERS(codeownersPath string) (*Lookup, error) {
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
	var owners []string
	if err := initDefaultLookupIfNeeded(); err != nil {
		return owners, err
	}

	rule, err := lookup.codeowners.Match(repoPath)
	if err != nil {
		return owners, err
	}

	if rule == nil {
		return owners, nil
	}

	for _, owner := range rule.Owners {
		owners = append(owners, owner.String())
	}
	return owners, nil
}

// IsOwnedBy finds out if a path is owned by one of multiple owners
func IsOwnedBy(repoPath string, ownersList []string) (bool, error) {
	// repoPath must be relative. Since grype 0.64.0, they send a leading '/'
	if strings.HasPrefix(repoPath, "/") {
		repoPath = strings.TrimLeft(repoPath, "/")
	}
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
