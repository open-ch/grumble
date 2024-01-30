package parse

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const jsonIndentSpacing = "    "
const jsonPrefix = ""

func getTestReport(t *testing.T, path string) string {
	t.Helper()

	rawBytes, err := os.ReadFile(path)
	assert.NoError(t, err)
	return string(rawBytes)
}
