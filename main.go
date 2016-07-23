package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// GIPClaims sets the JWT claims for Google Identity Platform.
type GIPClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

// FirebaseScopes defines scope for Firebase accounts defined in Google Identity Platform.
var FirebaseScopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/firebase.database",
}

// GIPAuthURL sets Google Identity Platform auth url.
const GIPAuthURL = "https://www.googleapis.com/oauth2/v4/token"

// ServiceAccount represents contents of service account keyfile.
type ServiceAccount struct {
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

func main() {

	keyfileName := "keyfile.json"
	keyfile, err := ioutil.ReadFile(keyfileName)
	if err != nil {
		log.Fatalf("Can't read keyfile: %s", err)
	}

	var account ServiceAccount
	if err := json.Unmarshal(keyfile, &account); err != nil {
		log.Fatalf("Can't unmarshal keyfile: %s", err)
	}

	// Create the Claims
	now := time.Now().Unix()
	claims := GIPClaims{
		Scope: strings.Join(FirebaseScopes, " "),
		StandardClaims: jwt.StandardClaims{
			Issuer:    account.ClientEmail,
			Audience:  GIPAuthURL,
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
		log.Fatalf("Parsing RSA private key failed: %s", err)
	}

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Creating jwt token string failed: %s", err)
	}

	// doing POST request to get access token
	resp, err := http.PostForm(GIPAuthURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {tokenString},
	})
	if err != nil {
		log.Fatalf("Sending post request to Google Identity Platform failed: %s", err)
	}
	log.Printf("Response: %+v\n", resp)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Read response body failed: %s", err)
	}

	log.Printf("Body: %s", string(body))
}
