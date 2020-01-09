//
// client.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"cloud.google.com/go/firestore"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/iterator"
)

type Client struct {
	ID          string
	Secret      string
	TenantID    string
	PlainSecret string
	Description string
}

type Tenant struct {
	ID          string
	Description string
}

type TenantID [8]byte

func (id TenantID) String() string {
	return base64.RawStdEncoding.EncodeToString(id[:])
}

func ParseTenantID(val string) (TenantID, error) {
	var id TenantID

	data, err := base64.RawStdEncoding.DecodeString(val)
	if err != nil {
		return id, err
	}
	if len(data) != len(id) {
		return id, fmt.Errorf("Invalid Tenant ID '%s'", val)
	}
	copy(id[:], data)

	return id, nil
}

func (c *Client) VerifyPassword(password string) error {
	plain, err := base64.RawStdEncoding.DecodeString(password)
	if err != nil {
		return err
	}
	hashed, err := base64.RawStdEncoding.DecodeString(c.Secret)
	if err != nil {
		return err
	}
	return bcrypt.CompareHashAndPassword(hashed, plain)
}

type ClientStore struct {
	ctx    context.Context
	client *firestore.Client
}

func NewClientStore() (*ClientStore, error) {
	ctx := context.Background()

	id, err := GetProjectID()
	if err != nil {
		return nil, err
	}

	client, err := firestore.NewClient(ctx, id)
	if err != nil {
		return nil, err
	}

	return &ClientStore{
		ctx:    ctx,
		client: client,
	}, nil
}

func (store *ClientStore) Close() error {
	if store.client != nil {
		return store.client.Close()
	}
	return nil
}

func (store *ClientStore) NewClient(tenant string, description string) (
	*Client, error) {

	var buf [16]byte

	tenantID, err := ParseTenantID(tenant)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Description: description,
		TenantID:    tenantID.String(),
	}

	_, err = rand.Read(buf[:8])
	if err != nil {
		return nil, err
	}
	client.ID = base64.RawStdEncoding.EncodeToString(buf[:8])

	_, err = rand.Read(buf[:])
	if err != nil {
		return nil, err
	}

	client.PlainSecret = base64.RawStdEncoding.EncodeToString(buf[:])

	hashed, err := bcrypt.GenerateFromPassword(buf[:], bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	client.Secret = base64.RawStdEncoding.EncodeToString(hashed)

	_, _, err = store.client.Collection("clients").Add(store.ctx,
		map[string]interface{}{
			"id":          client.ID,
			"secret":      client.Secret,
			"tenant":      client.TenantID,
			"description": client.Description,
		})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (store *ClientStore) Clients(id string) ([]*Client, error) {
	q := store.client.Collection("clients").Where("id", "==", id)
	iter := q.Documents(store.ctx)
	defer iter.Stop()

	var result []*Client

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		data := doc.Data()
		id, ok := data["id"].(string)
		if !ok {
			continue
		}
		secret, ok := data["secret"].(string)
		if !ok {
			continue
		}
		tenant, ok := data["tenant"].(string)
		if !ok {
			continue
		}
		description, ok := data["description"].(string)
		if !ok {
			continue
		}

		result = append(result, &Client{
			ID:          id,
			Secret:      secret,
			TenantID:    tenant,
			Description: description,
		})
	}

	return result, nil
}

func (store *ClientStore) NewTenant(description string) (*Tenant, error) {
	var buf [8]byte

	_, err := rand.Read(buf[:])
	if err != nil {
		return nil, err
	}

	tenant := &Tenant{
		ID:          base64.RawStdEncoding.EncodeToString(buf[:]),
		Description: description,
	}

	_, _, err = store.client.Collection("tenants").Add(store.ctx,
		map[string]interface{}{
			"id":          tenant.ID,
			"description": tenant.Description,
		})
	if err != nil {
		return nil, err
	}

	return tenant, nil
}
