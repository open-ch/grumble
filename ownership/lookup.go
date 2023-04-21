package ownership

import (
	"os"
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
func LoadFromCODEOWNERS(path string) (*Lookup, error) {
	file, err := os.Open(path)
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
func LookupFor(repoPath string) (string, error) {
	if err := initDefaultLookupIfNeeded(); err != nil {
		return "", err
	}

	rule, err := lookup.codeowners.Match(repoPath)
	if err != nil {
		return "", err
	}

	var owners []string
	for _, owner := range rule.Owners {
		owners = append(owners, owner.String())
	}
	return strings.Join(owners, ", "), nil
}

// IsOwnedBy finds out if a path is owned by one of multiple owners
func IsOwnedBy(repoPath string, ownersList []string) (bool, error) {
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
	l, err := LoadFromCODEOWNERS(viper.GetString("codeownersPath"))
	if err != nil {
		return err
	}
	SetLookup(l)

	return nil
}
