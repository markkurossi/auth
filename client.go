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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

type Client struct {
	ID       string
	Secret   string
	TenantID string
	Name     string
}

func (c *Client) CreateSecret(clientIDSecret []byte) error {
	id, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, clientIDSecret)
	mac.Write(id)

	c.Secret = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return nil
}

func VerifyClientCredentials(id, secret string, clientIDSecret []byte) bool {
	client := &Client{
		ID: id,
	}
	err := client.CreateSecret(clientIDSecret)
	if err != nil {
		return false
	}
	return client.Secret == secret
}

func UnmarshalClient(data map[string]interface{}) (*Client, error) {
	id, ok := data["id"].(string)
	if !ok {
		return nil, fmt.Errorf("No ID")
	}
	tenant, ok := data["tenant"].(string)
	if !ok {
		return nil, fmt.Errorf("No TenantID")
	}
	name, ok := data["name"].(string)
	if !ok {
		return nil, fmt.Errorf("No Name")
	}

	return &Client{
		ID:       id,
		TenantID: tenant,
		Name:     name,
	}, nil
}

type Tenant struct {
	ID   string
	Name string
}

func UnmarshalTenant(data map[string]interface{}) (*Tenant, error) {
	id, ok := data["id"].(string)
	if !ok {
		return nil, fmt.Errorf("No ID")
	}
	name, ok := data["name"].(string)
	if !ok {
		return nil, fmt.Errorf("No Name")
	}
	return &Tenant{
		ID:   id,
		Name: name,
	}, nil
}

type TenantID [8]byte

func (id TenantID) String() string {
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func ParseTenantID(val string) (TenantID, error) {
	var id TenantID

	data, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return id, err
	}
	if len(data) != len(id) {
		return id, fmt.Errorf("Invalid Tenant ID '%s'", val)
	}
	copy(id[:], data)

	return id, nil
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

func (store *ClientStore) NewClient(tenant string, name string,
	clientIDSecret []byte) (*Client, error) {

	var buf [16]byte

	tenantID, err := ParseTenantID(tenant)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Name:     name,
		TenantID: tenantID.String(),
	}

	_, err = rand.Read(buf[:8])
	if err != nil {
		return nil, err
	}
	client.ID = base64.RawURLEncoding.EncodeToString(buf[:8])

	err = client.CreateSecret(clientIDSecret)
	if err != nil {
		return nil, err
	}

	_, _, err = store.client.Collection("clients").Add(store.ctx,
		map[string]interface{}{
			"id":     client.ID,
			"tenant": client.TenantID,
			"name":   client.Name,
		})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (store *ClientStore) Clients() ([]*Client, error) {
	iter := store.client.Collection("clients").DocumentRefs(store.ctx)

	var result []*Client

	for {
		ref, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		doc, err := ref.Get(store.ctx)
		if err != nil {
			return nil, err
		}

		client, err := UnmarshalClient(doc.Data())
		if err != nil {
			return nil, err
		}
		result = append(result, client)
	}

	return result, nil
}

func (store *ClientStore) Client(id string) ([]*Client, error) {
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

		client, err := UnmarshalClient(doc.Data())
		if err != nil {
			return nil, err
		}

		result = append(result, client)
	}

	return result, nil
}

func (store *ClientStore) NewTenant(name string) (*Tenant, error) {
	var buf [8]byte

	_, err := rand.Read(buf[:])
	if err != nil {
		return nil, err
	}

	tenant := &Tenant{
		ID:   base64.RawURLEncoding.EncodeToString(buf[:]),
		Name: name,
	}

	_, _, err = store.client.Collection("tenants").Add(store.ctx,
		map[string]interface{}{
			"id":   tenant.ID,
			"name": tenant.Name,
		})
	if err != nil {
		return nil, err
	}

	return tenant, nil
}

func (store *ClientStore) Tenants() ([]*Tenant, error) {
	iter := store.client.Collection("tenants").DocumentRefs(store.ctx)

	var result []*Tenant

	for {
		ref, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		doc, err := ref.Get(store.ctx)
		if err != nil {
			return nil, err
		}

		tenant, err := UnmarshalTenant(doc.Data())
		if err != nil {
			return nil, err
		}
		result = append(result, tenant)
	}

	return result, nil
}

func (store *ClientStore) Tenant(id string) ([]*Tenant, error) {
	q := store.client.Collection("tenants").Where("id", "==", id)
	iter := q.Documents(store.ctx)
	defer iter.Stop()

	var result []*Tenant

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		tenant, err := UnmarshalTenant(doc.Data())
		if err != nil {
			return nil, err
		}

		result = append(result, tenant)
	}

	return result, nil
}

type Asset struct {
	Name string
	Data []byte
}

func UnmarshalAsset(data map[string]interface{}) (*Asset, error) {
	name, ok := data["name"].(string)
	if !ok {
		return nil, fmt.Errorf("No Name")
	}
	str, ok := data["data"].(string)
	if !ok {
		return nil, fmt.Errorf("No Data")
	}
	bytes, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return &Asset{
		Name: name,
		Data: bytes,
	}, nil
}

func (store *ClientStore) NewAsset(name string, data []byte) (*Asset, error) {
	asset := &Asset{
		Name: name,
		Data: data,
	}
	_, _, err := store.client.Collection("assets").Add(store.ctx,
		map[string]interface{}{
			"name": name,
			"data": base64.RawURLEncoding.EncodeToString(data),
		})
	if err != nil {
		return nil, err
	}
	return asset, nil
}

func (store *ClientStore) Asset(name string) ([]*Asset, error) {
	q := store.client.Collection("assets").Where("name", "==", name)
	iter := q.Documents(store.ctx)
	defer iter.Stop()

	var result []*Asset

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		asset, err := UnmarshalAsset(doc.Data())
		if err != nil {
			return nil, err
		}

		result = append(result, asset)
	}

	return result, nil
}
