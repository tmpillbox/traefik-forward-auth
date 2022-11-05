package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"
)

// GenericOAuth provider
type GenericOAuth struct {
	AuthURL      string   `long:"auth-url" env:"AUTH_URL" description:"Auth/Login URL"`
	TokenURL     string   `long:"token-url" env:"TOKEN_URL" description:"Token URL"`
	UserURL      string   `long:"user-url" env:"USER_URL" description:"URL used to retrieve user info"`
	ClientID     string   `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string   `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scopes       []string `long:"scope" env:"SCOPE" env-delim:"," default:"profile" default:"email" description:"Scopes"`
	TokenStyle   string   `long:"token-style" env:"TOKEN_STYLE" default:"header" choice:"header" choice:"query" description:"How token is presented when querying the User URL"`
	UserKey      string   `long:"user-key" env:"USER_KEY" default:"email" description:"Key in user URL body that contains username"`
	UserFormat   string   `long:"user-format" env:"USER_FORMAT" description:"Sprintf format to pass username through"`

	OAuthProvider
}

// Name returns the name of the provider
func (o *GenericOAuth) Name() string {
	return "generic-oauth"
}

// Setup performs validation and setup
func (o *GenericOAuth) Setup() error {
	// Check parmas
	if o.AuthURL == "" || o.TokenURL == "" || o.UserURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.generic-oauth.auth-url, providers.generic-oauth.token-url, providers.generic-oauth.user-url, providers.generic-oauth.client-id, providers.generic-oauth.client-secret must be set")
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.AuthURL,
			TokenURL: o.TokenURL,
		},
		Scopes: o.Scopes,
	}

	o.ctx = context.Background()

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *GenericOAuth) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *GenericOAuth) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *GenericOAuth) GetUser(token string) (User, error) {
	var user User

	req, err := http.NewRequest("GET", o.UserURL, nil)
	if err != nil {
		return user, err
	}

	if o.TokenStyle == "header" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	} else if o.TokenStyle == "query" {
		q := req.URL.Query()
		q.Add("access_token", token)
		req.URL.RawQuery = q.Encode()
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)

	if err == nil {
		var result map[string]interface{}
		err = json.Unmarshal(body, &result)
		if err == nil {
			username := result[o.UserKey].(string)
			if o.UserFormat != "" {
				username = fmt.Sprintf(o.UserFormat, username)
			}
			user.Email = username
		}
	}

	return user, err
}
