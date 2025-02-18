package format

import (
	"fmt"
	"io"

	"github.com/open-ch/grumble/grype"
	"github.com/open-ch/grumble/syft"
)

// Formatter can be used to format grype reports for output
// use NewFormatter to configure a new formatter.
type Formatter struct {
	format string
	writer io.Writer
}

// PrintDocument is a union type for grype and syft documents
type PrintDocument interface {
	*grype.Document | *syft.Document
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
func Print[T PrintDocument](formatter *Formatter, document T) error {
	var output string
	var err error
	switch formatter.format {
	case "json": //nolint:goconst
		output, err = renderJSON(document)
	case "pretty":
		output, err = renderPretty(document)
	case "prometheus": //nolint:goconst
		output, err = renderPrometheus(document)
	case "short":
		output, err = renderShort(document)
	default:
		return fmt.Errorf("invalid formatter print format configured: %s", formatter.format)
	}

	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(formatter.writer, "%s\n", output)
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
