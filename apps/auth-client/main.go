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
	"os"

	"github.com/markkurossi/auth"
)

var commands = map[string]func(store *auth.ClientStore){
	"client": cmdClient,
	"tenant": cmdTenant,
}

func main() {
	flag.Parse()

	store, err := auth.NewClientStore()
	if err != nil {
		log.Fatalf("auth.NewClientStore: %s\n", err)
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
	fn(store)
}
