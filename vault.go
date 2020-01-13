//
// vault.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package auth

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1beta1"
	api "github.com/markkurossi/cicd/api/auth"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"
)

type Vault struct {
	ctx       context.Context
	projectID string
	client    *secretmanager.Client
}

func NewVault() (*Vault, error) {
	ctx := context.Background()
	id, err := GetProjectID()
	if err != nil {
		return nil, err
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &Vault{
		ctx:       ctx,
		projectID: id,
		client:    client,
	}, nil
}

func (vault *Vault) Create(name string, data []byte) error {
	createReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", vault.projectID),
		SecretId: api.KEY_CLIENT_ID_SECRET,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}

	secret, err := vault.client.CreateSecret(vault.ctx, createReq)
	if err != nil {
		return err
	}

	addReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: data,
		},
	}

	_, err = vault.client.AddSecretVersion(vault.ctx, addReq)
	return err
}

func (vault *Vault) Get(name, version string) ([]byte, error) {
	if len(version) == 0 {
		version = "latest"
	}
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%s",
			vault.projectID, name, version),
	}
	resp, err := vault.client.AccessSecretVersion(vault.ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Payload.Data, nil
}
