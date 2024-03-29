//
// fn.go
//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	api "github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/cloudsdk/api/secretmanager"
	"github.com/markkurossi/go-libs/fn"
)

var (
	mux            *http.ServeMux
	projectID      string
	store          *api.ClientStore
	secretManager  *secretmanager.Client
	clientIDSecret []byte
	signatureKey   ed25519.PrivateKey
)

// Fatalf reports a fatal error and exits the process.
func Fatalf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

func init() {
	mux = http.NewServeMux()
	mux.HandleFunc("/token", Token)

	id, err := fn.GetProjectID()
	if err != nil {
		Fatalf("GetProjectID: %s\n", err)
	}
	projectID = id

	store, err = api.NewClientStore()
	if err != nil {
		Fatalf("NewClientStore: %s\n", err)
	}
	secretManager, err = secretmanager.NewClient()
	if err != nil {
		Fatalf("NewVault: %s\n", err)
	}
	clientIDSecret, err = secretManager.Get(api.KEY_CLIENT_ID_SECRET, "")
	if err != nil {
		Fatalf("Failed to get secret %s: %s\n", api.KEY_CLIENT_ID_SECRET, err)
	}
	data, err := secretManager.Get(api.KEY_TOKEN_SIGNATURE_KEY, "")
	if err != nil {
		Fatalf("Failed to get secret %s: %s\n",
			api.KEY_TOKEN_SIGNATURE_KEY, err)
	}
	signatureKey = ed25519.PrivateKey(data)
}

// Auth implements the Google Cloud Functions entrypoint.
func Auth(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}

// OAuthError defines OAuth2 errors
type OAuthError string

// OAuth2 errors
const (
	ErrorInvalidRequest       OAuthError = "invalid_request"
	ErrorInvalidClient        OAuthError = "invalid_client"
	ErrorInvalidGrant         OAuthError = "invalid_grant"
	ErrorUnauthorizedClient   OAuthError = "unauthorized_client"
	ErrorUnsupportedGrantType OAuthError = "unsupported_grant_type"
	ErrorInvalidScope         OAuthError = "invalid_scope"
)

// Errorf creates an HTTP error response.
func Errorf(w http.ResponseWriter, oauthError OAuthError,
	format string, a ...interface{}) {

	data, err := json.Marshal(map[string]string{
		"error":             string(oauthError),
		"error_description": fmt.Sprintf(format, a...),
	})
	if err != nil {
		Error500f(w, "json.Marshal: %s", err)
		return
	}

	w.Header().Set("Content-Type:", "application/json;charset=UTF-8")

	w.WriteHeader(http.StatusBadRequest)
	w.Write(data)
}

// Error500f creates an HTTP 500 error response.
func Error500f(w http.ResponseWriter, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), http.StatusInternalServerError)
}
