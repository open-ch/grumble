package format

import (
	"fmt"
	"io"

	"github.com/open-ch/grumble/grype"
)

// Formatter can be used to format grype reports for output
// use NewFormatter to configure a new formatter.
type Formatter struct {
	format string
	writer io.Writer
}

// NewFormatter configures a new formatter for handling grype documents
func NewFormatter(format string, writer io.Writer) *Formatter {
	f := &Formatter{
		format,
		writer,
	}
	return f
}

// Print renders the given document using the configured formatter
func (f *Formatter) Print(document *grype.Document) error {
	var renderFunction func(document *grype.Document) (string, error)
	switch f.format {
	case "json": //nolint:goconst
		renderFunction = renderJSON
	case "pretty":
		renderFunction = renderPretty
	case "prometheus": //nolint:goconst
		renderFunction = renderPrometheus
	case "short":
		renderFunction = renderShort
	default:
		return fmt.Errorf("invalid formatter print format configured: %s", f.format)
	}

	output, err := renderFunction(document)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f.writer, "%s\n", output)
	if err != nil {
		return err
	}
	return nil
}

// PrintDiff renders the given diff using the configured formatter
func (f *Formatter) PrintDiff(diff *grype.DocumentDiff) error {
	var renderFunction func(diff *grype.DocumentDiff) (string, error)
	switch f.format {
	case "json":
		renderFunction = renderDiffJSON
	case "prometheus":
		renderFunction = renderDiffPrometheus
	default:
		return fmt.Errorf("invalid formatter print format for DocumentDiff configured: %s", f.format)
	}

	output, err := renderFunction(diff)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f.writer, "%s\n", output)
	if err != nil {
		return err
	}
	return nil
}
