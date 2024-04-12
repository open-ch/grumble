package download

import (
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const simpleGrype = `{"descriptor": {}, "distro": {}, "matches": {}, "source": {}}`

func TestFileFromURL(t *testing.T) {
	var tests = []struct {
		name          string
		requestURL    string
		expectedBody  string
		expectedError bool
	}{
		{
			name:         "Makes authenticated requests",
			requestURL:   "https://download.example.com/security/latest_grype.json",
			expectedBody: simpleGrype,
		},
		{
			name:          "Fails",
			requestURL:    "https://download.example.com/security/nonexistant_grype.json",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, "Not Found"))
			httpmock.RegisterMatcherResponder("GET", "https://download.example.com/security/latest_grype.json",
				httpmock.HeaderExists("Authorization"),
				httpmock.NewStringResponder(200, simpleGrype))
			viper.Set("usernameEnvVar", "GRUMBLE_USERNAME")
			viper.Set("passwordEnvVar", "GRUMBLE_PASSWORD")
			t.Setenv("GRUMBLE_USERNAME", "grumble")
			t.Setenv("GRUMBLE_PASSWORD", "elbmurg")

			outputJSON, err := FileFromURL(tc.requestURL)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBody, string(outputJSON))
			}
		})
	}
}

func TestGetAuthCredentials(t *testing.T) {
	var tests = []struct {
		name         string
		mockEnv      map[string]string
		expectedAuth *auth
	}{
		{
			name: "Reads auth from configured env vars",
			mockEnv: map[string]string{
				"GRUMBLE_USERNAME": "grumble",
				"GRUMBLE_PASSWORD": "elbmurg",
			},
			expectedAuth: &auth{username: "grumble", password: "elbmurg"},
		},
		{
			name: "No auth if username is empty/unset",
			mockEnv: map[string]string{
				"GRUMBLE_USERNAME": "",
				"GRUMBLE_PASSWORD": "elbmurg",
			},
		},
		{
			name: "No auth if password is empty/unset",
			mockEnv: map[string]string{
				"GRUMBLE_USERNAME": "grumble",
				"GRUMBLE_PASSWORD": "",
			},
		},
		{
			name: "No auth if both are empty/unset",
			mockEnv: map[string]string{
				"GRUMBLE_USERNAME": "",
				"GRUMBLE_PASSWORD": "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("usernameEnvVar", "GRUMBLE_USERNAME")
			viper.Set("passwordEnvVar", "GRUMBLE_PASSWORD")
			for k, v := range tc.mockEnv {
				t.Setenv(k, v)
			}

			auth := getAuthCredentials()

			assert.Equal(t, tc.expectedAuth, auth)
		})
	}
}
