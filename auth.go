// Package auth implements obtaining authentication token for Service Account
// that can be used for Firebase (https://firebase.google.com).
package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// gipClaims sets the JWT claims for Google Identity Platform.
type gipClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

// firebaseScopes defines scope for Firebase accounts defined in Google Identity Platform.
var FirebaseScopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/firebase.database",
}

// gipAuthURL sets Google Identity Platform auth url.
const gipAuthURL = "https://www.googleapis.com/oauth2/v4/token"

// serviceAccount represents contents of service account keyfile.
type serviceAccount struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// Token is a Google Identity Platform auth token.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// GetToken returns Auth Token
func GetToken(keyfile string) (*Token, error) {

	keyfileData, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("Can't read keyfile: %s", err)
	}

	var account serviceAccount
	if err := json.Unmarshal(keyfileData, &account); err != nil {
		return nil, fmt.Errorf("Can't unmarshal keyfile: %s", err)
	}

	// Create the Claims
	now := time.Now().Unix()
	claims := gipClaims{
		Scope: strings.Join(FirebaseScopes, " "),
		StandardClaims: jwt.StandardClaims{
			Issuer:    account.ClientEmail,
			Audience:  gipAuthURL,
			IssuedAt:  now,
			ExpiresAt: now + (60 * 60),
			Subject:   account.ClientEmail,
		},
	}

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Reading privateKey contents
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(account.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("Parsing RSA private key failed: %s", err)
	}

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Creating jwt token string failed: %s", err)
	}

	// doing POST request to get access token
	resp, err := http.PostForm(gipAuthURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {tokenString},
	})
	if err != nil {
		return nil, fmt.Errorf("Sending post request to Google Identity Platform failed: %s", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Read response body failed: %s", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%+v", struct {
			StatusCode int
			Body       string
		}{resp.StatusCode, string(body)})
	}

	authToken := Token{}
	if err := json.Unmarshal(body, &authToken); err != nil {
		return nil, fmt.Errorf("Can't unmarshal auth token from body: %s", err)
	}

	return &authToken, nil
}
