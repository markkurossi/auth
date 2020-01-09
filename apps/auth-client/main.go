//
// main.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/markkurossi/auth"
)

func main() {
	create := flag.String("c", "", "Create new client with DESCRIPTION")
	query := flag.String("q", "", "Query clients with ID")
	secret := flag.String("s", "", "Client secret")
	tenant := flag.String("T", "", "Create new tenant with DESCRIPTION")
	tenantID := flag.String("t", "", "Tenant ID")
	flag.Parse()

	store, err := auth.NewClientStore()
	if err != nil {
		log.Fatalf("auth.NewClientStore: %s\n", err)
	}

	if len(*tenant) > 0 {
		tenant, err := store.NewTenant(*tenant)
		if err != nil {
			log.Fatalf("Failed to create tenant: %s\n", err)
		}
		fmt.Printf("Tenant created:\nID\t\t%s\nDescription:\t%s\n",
			tenant.ID, tenant.Description)
		*tenantID = tenant.ID
	}

	if len(*create) > 0 {
		client, err := store.NewClient(*tenantID, *create)
		if err != nil {
			log.Fatalf("Failed to create client: %s\n", err)
		}

		fmt.Printf("Client created:\nID:\t\t%s\nTenantID:\t%s\nDescription:\t%s\nSecret:\t\t%s\n",
			client.ID, client.TenantID, client.Description, client.PlainSecret)
	}
	if len(*query) > 0 {
		clients, err := store.Clients(*query)
		if err != nil {
			log.Fatalf("Failed to query clients: %s\n", err)
		}

		for _, client := range clients {
			fmt.Printf("%s\t%s\n", client.ID, client.Description)

			if len(*secret) > 0 {
				err = client.VerifyPassword(*secret)
				if err != nil {
					fmt.Printf("  Secret mismatch: %s\n", err)
				}
			}
		}
	}
}
