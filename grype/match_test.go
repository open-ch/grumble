package grype

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchUniqueID(t *testing.T) {
	var tests = []struct {
		name        string
		match       Match // Uses testMatches defined in filters_test.go
		expectedUID string
	}{
		{
			name:        "Test 1",
			match:       testMatches["low:cve1:fixed"],
			expectedUID: "low:cve1:pkg:golang/example.com/example@v1.0.0:2c9911243516acb8c6e0a32f7062fe9feb02894eb2d1c29e387793ef7bc3b0da",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid := tc.match.UniqueID()

			assert.Equal(t, tc.expectedUID, uid)
		})
	}
}
