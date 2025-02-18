package format

import (
	"encoding/json"

	"github.com/open-ch/grumble/grype"
)

const jsonIndentSpacing = "    "
const jsonPrefix = ""

func renderJSON[T PrintDocument](document T) (string, error) {
	rawJSON, err := json.MarshalIndent(document, jsonPrefix, jsonIndentSpacing)
	return string(rawJSON), err
}

func renderDiffJSON(diff *grype.DocumentDiff) (string, error) {
	rawJSON, err := json.MarshalIndent(diff, jsonPrefix, jsonIndentSpacing)
	return string(rawJSON), err
}
