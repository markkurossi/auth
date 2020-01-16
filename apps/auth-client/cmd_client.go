//
// cmd_client.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/markkurossi/cicd/api/auth"
	"github.com/markkurossi/cicd/api/secretmanager"
)

type clientParams struct {
	store         *auth.ClientStore
	secretManager *secretmanager.Client
	tenant        string
}

var clientCmds = map[string]func(params clientParams, args []string) error{
	"create": clientCreate,
	"list":   clientList,
	"get":    clientGet,
}

func cmdClient(store *auth.ClientStore, secretManager *secretmanager.Client) {
	tenant := flag.String("t", "", "Tenant ID")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Printf("Possible commands are:\n")
		for cmd := range clientCmds {
			fmt.Printf(" - %s\n", cmd)
		}
		return
	}

	params := clientParams{
		store:         store,
		secretManager: secretManager,
		tenant:        *tenant,
	}

	args := flag.Args()

	fn, ok := clientCmds[args[0]]
	if !ok {
		fmt.Printf("Unknown command %s\n", args[0])
		os.Exit(1)
	}
	err := fn(params, args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func clientCreate(params clientParams, args []string) error {
	if len(args) != 1 {
		flag.Usage()
		fmt.Printf("Usage: client create NAME\n")
		os.Exit(1)
	}

	secret, err := params.secretManager.Get(auth.KEY_CLIENT_ID_SECRET, "")
	if err != nil {
		fmt.Printf("Failed to get client ID secret: %s\n", err)
		os.Exit(1)
	}

	client, err := params.store.NewClient(params.tenant, args[0], secret)
	if err != nil {
		fmt.Printf("Failed to create client: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Client created:")
	fmt.Printf("ID:\t\t%s\n", client.ID)
	fmt.Printf("Secret:\t\t%s\n", client.Secret)
	fmt.Printf("TenantID:\t%s\n", client.TenantID)
	fmt.Printf("Name:\t\t%s\n", client.Name)
	fmt.Printf("Authorization:\tBearer %s\n",
		auth.BasicAuth(client.ID, client.Secret))

	return nil
}

func clientList(params clientParams, args []string) error {
	clients, err := params.store.Clients()
	if err != nil {
		return err
	}

	for _, c := range clients {
		fmt.Printf("%s\t%s\n", c.ID, c.Name)
	}

	return nil
}

func clientGet(params clientParams, args []string) error {
	if len(args) == 0 {
		fmt.Printf("Usage: client get ID...\n")
		os.Exit(1)
	}

	secret, err := params.secretManager.Get(auth.KEY_CLIENT_ID_SECRET, "")
	if err != nil {
		fmt.Printf("Failed to get client ID secret: %s\n", err)
		os.Exit(1)
	}

	for _, id := range args {
		matches, err := params.store.Client(id)
		if err != nil {
			fmt.Printf("%s:\t%s\n", id, err)
			continue
		}
		for _, c := range matches {
			err = c.CreateSecret(secret)
			if err != nil {
				fmt.Printf("Failed to create client secret: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("ID:\t\t%s\n", c.ID)
			fmt.Printf("Secret:\t\t%s\n", c.Secret)
			fmt.Printf("TenantID:\t%s\n", c.TenantID)
			fmt.Printf("Name:\t\t%s\n", c.Name)
		}
	}
	return nil
}
