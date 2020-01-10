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

	"github.com/markkurossi/auth"
	api "github.com/markkurossi/cicd/api/auth"
)

type clientParams struct {
	store  *auth.ClientStore
	tenant string
	secret string
}

var clientCmds = map[string]func(params clientParams, args []string) error{
	"create": clientCreate,
	"list":   clientList,
	"get":    clientGet,
}

func cmdClient(store *auth.ClientStore) {
	tenant := flag.String("t", "", "Tenant ID")
	secret := flag.String("s", "", "Client secret")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Printf("Possible commands are:\n")
		for cmd := range clientCmds {
			fmt.Printf(" - %s\n", cmd)
		}
		return
	}

	params := clientParams{
		store:  store,
		tenant: *tenant,
		secret: *secret,
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
		fmt.Printf("Usage: client create DESCRIPTION\n")
		os.Exit(1)
	}

	client, err := params.store.NewClient(params.tenant, args[0])
	if err != nil {
		fmt.Printf("Failed to create client: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Client created:")
	fmt.Printf("ID:\t\t%s\n", client.ID)
	fmt.Printf("TenantID:\t%s\n", client.TenantID)
	fmt.Printf("Description:\t%s\n", client.Description)
	fmt.Printf("Secret:\t\t%s\n", client.PlainSecret)
	fmt.Printf("Authorization:\tBearer %s\n",
		api.BasicAuth(client.ID, client.PlainSecret))

	return nil
}

func clientList(params clientParams, args []string) error {
	clients, err := params.store.Clients()
	if err != nil {
		return err
	}

	for _, c := range clients {
		fmt.Printf("%s\t%s\n", c.ID, c.Description)
	}

	return nil
}

func clientGet(params clientParams, args []string) error {
	if len(args) == 0 {
		fmt.Printf("Usage: client get ID...\n")
		os.Exit(1)
	}

	for _, id := range args {
		matches, err := params.store.Client(id)
		if err != nil {
			fmt.Printf("%s:\t%s\n", id, err)
			continue
		}
		for _, c := range matches {
			fmt.Printf("ID:\t\t%s\n", c.ID)
			fmt.Printf("TenantID:\t%s\n", c.TenantID)
			fmt.Printf("Description:\t%s\n", c.Description)
			if len(params.secret) > 0 {
				err = c.VerifyPassword(params.secret)
				if err != nil {
					fmt.Printf("Secret:\t\t\u2717 %s\n", err)
				} else {
					fmt.Printf("Secret:\t\t\u2713\n")
				}
			}
		}
	}
	return nil
}
