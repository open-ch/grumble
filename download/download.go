package download

import (
	"github.com/spf13/viper"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const HTTP_TIMEOUT = 5 * time.Second

type auth struct {
	username string
	password string
}

// FileFromURL fetches the given report using basic auth and saves it as a temp file,
// if successful it returns  the path of the file.
// The credentials are read from env variables, their names are defined through the viper config
//
// defaults: GRUMBLE_USERNAME, GRUMBLE_PASSWORD
func FileFromURL(url string) ([]byte, error) {
	client := http.Client{Timeout: HTTP_TIMEOUT}

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	auth := getAuthCredentials()
	if auth == nil {
		return nil, errors.New("unable to lookup authentication credentials")
	}
	req.SetBasicAuth(auth.username, auth.password)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return resBody, fmt.Errorf("unexpected response code %d", res.StatusCode)
	}

	return resBody, nil
}

func getAuthCredentials() *auth {
	usernameEnvVar := viper.GetString("usernameEnvVar")
	passwordEnvVar := viper.GetString("passwordEnvVar")

	username := os.Getenv(usernameEnvVar)
	if username == "" {
		return nil
	}
	password := os.Getenv(passwordEnvVar)
	if password == "" {
		return nil
	}

	return &auth{
		username,
		password,
	}
}
