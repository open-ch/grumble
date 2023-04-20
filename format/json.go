package format

import (
	"encoding/json"

	"github.com/open-ch/grumble/grype"
)

const jsonIndentSpacing = "    "
const jsonPrefix = ""

func renderJSON(document *grype.Document) (string, error) {
	rawJSON, err := json.MarshalIndent(document, jsonPrefix, jsonIndentSpacing)
	return string(rawJSON), err
}
