//
// token.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package auth

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/markkurossi/cicd/api/auth"
	"github.com/markkurossi/go-libs/tlv"
)

type AccessToken tlv.Values

func (t AccessToken) Marshal() (string, error) {
	data, err := tlv.Values(t).Marshal()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func Token(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s: %s\n", r.Method, r.URL.Path)

	if r.Method != "POST" {
		Errorf(w, ErrorInvalidRequest, "Invalid method %s", r.Method)
		return
	}

	err := r.ParseForm()
	if err != nil {
		Error500f(w, "ioutil.ReadAll: %s\n", err)
	}

	log.Printf("Form: %v\n", r.Form)

	var client Client

	client.ID = r.Form.Get("client_id")
	client.Secret = r.Form.Get("client_secret")
	if len(client.ID) == 0 || len(client.Secret) == 0 {
		Errorf(w, ErrorInvalidClient, "No client credentials")
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

func tokenResponse(w http.ResponseWriter, token AccessToken) {
	str, err := token.Marshal()
	if err != nil {
		Error500f(w, "token.Marshal: %s", err)
		return
	}

	data, err := json.Marshal(map[string]string{
		"access_token": str,
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
	client Client) {

	tokenResponse(w, AccessToken{
		tlv.Type(auth.T_TENANT_ID): client.TenantID,
		tlv.Type(auth.T_CLIENT_ID): client.ID,
		tlv.Type(auth.T_SCOPE): tlv.Values{
			tlv.Type(auth.SCOPE_ADMIN): true,
		},
	})
}
