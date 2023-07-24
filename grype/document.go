package grype

//revive:disable:nested-structs
//revive:disable:var-naming

import (
	"time"
)

// Document allows unmarshalling grype json reports into go.
// Initial structct auto generated using gojsonstruct and manually
// split afterwards.
// example:
// go install github.com/twpayne/go-jsonstruct/v2/cmd/gojsonstruct@latest
// wget SCRUBBED-URL
// cat grype-panta-latest.json | gojsonstruct > new.struct
// diff -y grype_0.64.1_gojsonstruct new.struct
// NOTE: we do NOT import "github.com/anchore/grype/grype/presenter/models"
//
//	because that would bring in too many dependencies.
type Document struct {
	Descriptor     Descriptor `json:"descriptor"`
	Distro         Distro     `json:"distro"`
	Matches        []Match    `json:"matches"`
	IgnoredMatches []Match    `json:"ignoredMatches,omitempty"`
	Source         Source     `json:"source"`
}

// Descriptor info of a Grype Document
type Descriptor struct {
	Configuration struct {
		AddCpesIfNone     bool   `json:"add-cpes-if-none"`
		ByCve             bool   `json:"by-cve"`
		CheckForAppUpdate bool   `json:"check-for-app-update"`
		ConfigPath        string `json:"configPath"`
		DB                struct {
			AutoUpdate            bool   `json:"auto-update"`
			CaCert                string `json:"ca-cert"`
			CacheDir              string `json:"cache-dir"`
			MaxAllowedBuiltAge    int    `json:"max-allowed-built-age"`
			UpdateURL             string `json:"update-url"`
			ValidateAge           bool   `json:"validate-age"`
			ValidateByHashOnStart bool   `json:"validate-by-hash-on-start"`
		} `json:"db"`
		Dev struct {
			ProfileCPU bool `json:"profile-cpu"`
			ProfileMem bool `json:"profile-mem"`
		} `json:"dev"`
		Distro          string   `json:"distro"`
		Exclude         []string `json:"exclude"`
		ExternalSources struct {
			Enable bool `json:"enable"`
			Maven  struct {
				BaseURL              string `json:"baseUrl"`
				SearchUpstreamBySha1 bool   `json:"searchUpstreamBySha1"`
			} `json:"maven"`
		} `json:"externalSources"`
		FailOnSeverity string       `json:"fail-on-severity"`
		File           string       `json:"file"`
		Ignore         []IgnoreRule `json:"ignore"`
		Log            struct {
			File       string `json:"file"`
			Level      string `json:"level"`
			Structured bool   `json:"structured"`
		} `json:"log"`
		Match struct {
			Dotnet struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"dotnet"`
			Golang struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"golang"`
			Java struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"java"`
			Javascript struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"javascript"`
			Python struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"python"`
			Ruby struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"ruby"`
			Stock struct {
				UsingCpes bool `json:"using-cpes"`
			} `json:"stock"`
		} `json:"match"`
		Name               string   `json:"name"`
		OnlyFixed          bool     `json:"only-fixed"`
		OnlyNotfixed       bool     `json:"only-notfixed"`
		Output             []string `json:"output"`
		OutputTemplateFile string   `json:"output-template-file"`
		Platform           string   `json:"platform"`
		Quiet              bool     `json:"quiet"`
		Registry           struct {
			Auth                  []any `json:"auth"`
			InsecureSkipTlSVerify bool  `json:"insecure-skip-tls-verify"`
			InsecureUseHTTP       bool  `json:"insecure-use-http"`
		} `json:"registry"`
		Search struct {
			IndexedArchives   bool   `json:"indexed-archives"`
			Scope             string `json:"scope"`
			UnindexedArchives bool   `json:"unindexed-archives"`
		} `json:"search"`
		ShowSuppressed bool `json:"show-suppressed"`
		Verbosity      int  `json:"verbosity"`
	} `json:"configuration"`
	DB struct {
		Built         time.Time `json:"built"`
		Checksum      string    `json:"checksum"`
		Error         any       `json:"error"`
		Location      string    `json:"location"`
		SchemaVersion int       `json:"schemaVersion"`
	} `json:"db"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Distro info of a Grype Document
type Distro struct {
	IDLike  any    `json:"idLike"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Source info of a Grype Document
type Source struct {
	Target string `json:"target"`
	Type   string `json:"type"`
}
