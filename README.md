# Grumble
      ________                   ___.   .__
     /  _____/______ __ __  _____\_ |__ |  |   ____
    /   \  __\_  __ \  |  \/     \| __ \|  | _/ __ \
    \    \_\  \  | \/  |  /  Y Y  \ \_\ \  |_\  ___/
     \______  /__|  |____/|__|_|  /___  /____/\___  >
            \/                  \/    \/          \/

At its heart grumble is an alternate formatter for [grype]
output with a few more features to make it useful in a monorepo setting.
Grumble has `CODEOWNERS` integration (see [GitHub code owners]) and filtering
(e.g. to make it easy to show detected vulnerability for one team only).

What grumble needs to run is:
* The output of a [grype] scan in json
* To be executed inside (working directory) a git repository with a `CODEOWNERS` file

It will combine the two and enrich the output with the name of teams that own various
paths where vulnerabilities are detected.

Example:
```sh
# Install grype (see https://github.com/anchore/grype)
# Install grumble:
go install github.com/open-ch/grumble@latest

# Generate scan report:
grype . -o json > test.json

# Parse resutls
grumble parse --input ./test.json
```

The intended use including CI/CD is as follows:
1. The CI/CD pipeline of the repository runs grype and uploads the scan results to a file repository
2. There is a `grumble.config.yaml` in the root of the repository pointing to that file and authentication settings
3. `grumble fetch` is run from inside the repository allowing it to fetch the latest scan results and
   display the vunlerabilities including teams owning those paths thanks to the `CODEOWNERS` file.

[grype]: https://github.com/anchore/grype
[GitHub code owners]: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

## Output formats

The `--format` flag can be used with the `parse` and `fetch` commands to select a different output format.

Available formats:
* __pretty (default):__ Pretty output with most important information about each vulnerability
* __short:__ Pretty and concise output, only 1 line per vulnerability
* __json:__ Outputs the results back in grype json format, useful for filtering
* __prometheus:__ Count of the vulnerabilities grouped and labeled by artifact, codeowners, id (CVE), severity, path and licenses. Useful for monitoring.

## Installation
The simplest install: `go install github.com/open-ch/grumble@latest`

To tweak the code using a local copy:
```sh
# Clone this repo to somewhere
git clone git@github.com:open-ch/grumble.git
cd grumble

# Install grumble
go install ./...

# The binary should be in $GOPATH/bin
ls `go env GOPATH`/bin
```

## Configuration

We use viper to store the config so in order of preference we will use:
1. Flag values (where applicable)
2. ENV variable
3. Value in `$HOME/.config/grumble/grumble.config.yaml`

Sample config:
```yaml
# Default url to use with the 'grumble fetch' command
fetchUrl: https://example.com/scan-results/grype-latest.json

# Read codeowners file from a different path (relative to git repository root)
# (default: "CODEOWNERS")
codeownersPath: .github/CODEOWNERS

# Read basic auth from different environment variables
# (default: "GRUMBLE_USERNAME", "GRUMBLE_PASSWORD")
usernameEnvVar: MY_PROJECT_USERNAME
passwordEnvVar: MY_PROJECT_PASSWORD

# Sets name of metric when using prometheus output format
# (default: "grumble_vulnerability")
prometheusMetricName: my_project_vulnerability
```
