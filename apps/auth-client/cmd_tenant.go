//
// cmd_tenant.go
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
)

var tenantCmds = map[string]func(store *auth.ClientStore, args []string) error{
	"create": tenantCreate,
	"list":   tenantList,
	"get":    tenantGet,
}

func cmdTenant(store *auth.ClientStore) {
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Printf("Possible commands are:\n")
		for cmd := range tenantCmds {
			fmt.Printf(" - %s\n", cmd)
		}
		return
	}

	args := flag.Args()

	fn, ok := tenantCmds[args[0]]
	if !ok {
		fmt.Printf("Unknown command %s\n", args[0])
		os.Exit(1)
	}
	err := fn(store, args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func tenantCreate(store *auth.ClientStore, args []string) error {
	if len(args) != 1 {
		fmt.Printf("Usage: tenant create DESCRIPTION\n")
		os.Exit(1)
	}
	tenant, err := store.NewTenant(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("Tenant created:\nID\t\t%s\nDescription:\t%s\n",
		tenant.ID, tenant.Description)
	return nil
}

func tenantList(store *auth.ClientStore, args []string) error {
	tenants, err := store.Tenants()
	if err != nil {
		return err
	}

	for _, t := range tenants {
		fmt.Printf("%s\t%s\n", t.ID, t.Description)
	}
	return nil
}

func tenantGet(store *auth.ClientStore, args []string) error {
	if len(args) == 0 {
		fmt.Printf("Usage: tenant get ID...\n")
		os.Exit(1)
	}

	for _, id := range args {
		matches, err := store.Tenant(id)
		if err != nil {
			fmt.Printf("%s:\t%s\n", id, err)
			continue
		}
		for _, t := range matches {
			fmt.Printf("%s\t%s\n", t.ID, t.Description)
		}
	}
	return nil
}
