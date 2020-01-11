//
// token.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/markkurossi/cicd/api/auth"
	"github.com/markkurossi/go-libs/tlv"
	"golang.org/x/crypto/ed25519"
)

func Token(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s: %s\n", r.Method, r.URL.Path)

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

	store, err := NewClientStore()
	if err != nil {
		Error500f(w, "NewClientStore: %s", err)
		return
	}
	clients, err := store.Client(clientID)
	if err != nil {
		Error500f(w, "NewClientStore: %s", err)
		return
	}

	var client *Client
	for _, c := range clients {
		if c.VerifyPassword(clientSecret) == nil {
			client = c
			break
		}
	}
	if client == nil {
		Errorf(w, ErrorInvalidClient, "Client authentication failed")
		return
	}

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

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		Error500f(w, "ed25519.GenerateKey: %s", err)
		return
	}

	signature := ed25519.Sign(priv, valuesData)

	token := tlv.Values{
		auth.TOKEN_VALUES:    valuesData,
		auth.TOKEN_SIGNATURE: signature,
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
	client *Client) {

	tokenResponse(w, tlv.Values{
		auth.T_TENANT_ID: client.TenantID,
		auth.T_CLIENT_ID: client.ID,
		auth.T_SCOPE: tlv.Values{
			auth.SCOPE_ADMIN: true,
		},
	})
}
