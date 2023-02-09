//
// token.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	api "github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/go-libs/tlv"
)

// Token implements the "/token" URI handler.
func Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		Errorf(w, ErrorInvalidRequest, "Invalid method %s", r.Method)
		return
	}

	err := r.ParseForm()
	if err != nil {
		Error500f(w, "ioutil.ReadAll: %s", err)
		return
	}

	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if len(clientID) == 0 || len(clientSecret) == 0 {
		Errorf(w, ErrorInvalidClient, "No client credentials")
		return
	}

	// Verify client ID and secret.
	if !api.VerifyClientCredentials(clientID, clientSecret, clientIDSecret) {
		Errorf(w, ErrorInvalidClient, "Client authentication failed")
		return
	}

	// Get client information.

	clients, err := store.Client(clientID)
	if err != nil {
		Error500f(w, "store.Client: %s", err)
		return
	}
	if len(clients) == 0 {
		Errorf(w, ErrorInvalidClient, "Client authentication failed")
		return
	}

	client := clients[0]

	grantType := r.Form.Get("grant_type")
	if len(grantType) == 0 {
		Errorf(w, ErrorInvalidRequest, "No 'grant_type'")
		return
	}

	switch grantType {
	case "client_credentials":
		clientCredentialsGrant(w, r, client)

	default:
		Errorf(w, ErrorInvalidGrant, "Invalid grant type '%s'", grantType)
		return
	}
}

func tokenResponse(w http.ResponseWriter, values tlv.Values) {
	valuesData, err := values.Marshal()
	if err != nil {
		Error500f(w, "values.Marshal: %s", err)
		return
	}

	signature := ed25519.Sign(signatureKey, valuesData)

	token := tlv.Values{
		api.TOKEN_VALUES:    values,
		api.TOKEN_SIGNATURE: signature,
	}

	tokenData, err := token.Marshal()
	if err != nil {
		Error500f(w, "token.Marshal: %s", err)
		return
	}

	data, err := json.Marshal(map[string]string{
		"access_token": base64.RawURLEncoding.EncodeToString(tokenData),
		"token_type":   "bearer",
	})
	if err != nil {
		Error500f(w, "json.Marshal: %s", err)
		return
	}

	w.Header().Set("Content-Type:", "application/json;charset=UTF-8")
	w.Write(data)
}

func clientCredentialsGrant(w http.ResponseWriter, r *http.Request,
	client *api.Client) {

	fmt.Printf("Granting access token for client %s (tenant %s)\n",
		client.Name, client.TenantID)

	now := time.Now()

	tokenResponse(w, tlv.Values{
		api.T_TENANT_ID:  client.TenantID,
		api.T_CLIENT_ID:  client.ID,
		api.T_NOT_BEFORE: uint64(now.Unix()),
		api.T_NOT_AFTER:  uint64(now.Add(24 * time.Hour).Unix()),
		api.T_SCOPE: tlv.Values{
			api.SCOPE_ADMIN: true,
		},
	})
}
