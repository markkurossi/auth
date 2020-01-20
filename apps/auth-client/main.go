//
// main.go
//
// Copyright (c) 2020 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/cloudsdk/api/secretmanager"
)

var commands = map[string]func(store *auth.ClientStore,
	secretManager *secretmanager.Client){
	"client": cmdClient,
	"key":    cmdKey,
	"tenant": cmdTenant,
}

func main() {
	flag.Parse()

	store, err := auth.NewClientStore()
	if err != nil {
		log.Fatalf("auth.NewClientStore: %s\n", err)
	}
	secretManager, err := secretmanager.NewClient()
	if err != nil {
		fmt.Printf("auth.NewVault: %s\n", err)
		os.Exit(1)
	}

	arg0 := os.Args[0]

	if len(flag.Args()) == 0 {
		flag.Usage()
		fmt.Printf("Possible command groups are:\n")
		for cmd := range commands {
			fmt.Printf(" - %s\n", cmd)
		}
		return
	}

	os.Args = flag.Args()
	fn, ok := commands[flag.Arg(0)]
	if !ok {
		fmt.Printf("Unknown command: %s\n", flag.Arg(0))
		os.Exit(1)
	}
	flag.CommandLine = flag.NewFlagSet(fmt.Sprintf("%s %s", arg0, os.Args[0]),
		flag.ExitOnError)
	fn(store, secretManager)
}
