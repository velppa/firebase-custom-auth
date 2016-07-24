# Firebase custom auth for Service Accounts

This Go package implements obtaining authentication token for Service Account that can be used for [Firebase].

## Installation

    go get github.com/schmooser/firebase-custom-auth

## Documentation

[Godoc](https://godoc.org/github.com/schmooser/firebase-custom-auth)

## Usage

1. [Create Service Account](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount), get keyfile from the Console
2. Use this keyfile to obtain auth token:

        token, err := auth.GetToken("keyfile.json")
        if err != nil {
          log.Fatalf("Failed to receive token: %s", err)
        }
        log.Printf("Token: %+v", token)

## Dependencies

* [jwt-go](https://github.com/dgrijalva/jwt-go)

## Links
* [Firebase Database REST API User Authentication](https://firebase.google.com/docs/reference/rest/database/user-auth)
* [Google Identity Platform - Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
- Inspiration - [appengine-firebase-custom-auth](https://github.com/k2wanko-sandbox/appengine-firebase-custom-auth)

[Firebase]: https://firebase.google.com
