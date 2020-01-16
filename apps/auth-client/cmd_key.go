//
// cmd_key.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/markkurossi/cicd/api/auth"
	"github.com/markkurossi/cicd/api/secretmanager"
	"golang.org/x/crypto/ed25519"
)

type keyParams struct {
	store         *auth.ClientStore
	secretManager *secretmanager.Client
}

var keyCmds = map[string]func(params keyParams, args []string) error{
	"create": keyCreate,
	"get":    keyGet,
}

func cmdKey(store *auth.ClientStore, secretManager *secretmanager.Client) {
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Printf("Possible commands are:\n")
		for cmd := range keyCmds {
			fmt.Printf(" - %s\n", cmd)
		}
		return
	}

	params := keyParams{
		store:         store,
		secretManager: secretManager,
	}

	args := flag.Args()
	fn, ok := keyCmds[args[0]]
	if !ok {
		fmt.Printf("Unknown command %s\n", args[0])
		os.Exit(1)
	}
	err := fn(params, args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if true {
		return
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("GenerateKey: %s\n", err)
		os.Exit(1)
	}

	msg := "Hello, world!"
	hashed := sha256.Sum256([]byte(msg))

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256,
		hashed[:])
	if err != nil {
		fmt.Printf("SignPKCS1v15: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signature:\n%s", hex.Dump(signature))
	fmt.Printf("Length: %d\n", len(signature))

	_, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("ed25519.GenerateKey: %s\n", err)
		os.Exit(1)
	}

	sig2 := ed25519.Sign(edpriv, []byte(msg))
	fmt.Printf("Signature:\n%s", hex.Dump(sig2))
	fmt.Printf("Length: %d\n", len(sig2))
}

func keyCreate(params keyParams, args []string) error {
	if len(args) == 0 {
		fmt.Printf("Usage: key create TYPE...\nWhere type is:\n")
		fmt.Printf(" - %s\tOAuth2 Client ID secret\n",
			auth.KEY_CLIENT_ID_SECRET)
		fmt.Printf(" - %s\tToken signature keypair\n",
			auth.KEY_TOKEN_SIGNATURE_KEY)
		return nil
	}

	for _, arg := range args {
		switch arg {
		case auth.KEY_CLIENT_ID_SECRET:
			var buf [64]byte

			_, err := rand.Read(buf[:])
			if err != nil {
				return err
			}

			err = params.secretManager.Create(auth.KEY_CLIENT_ID_SECRET, buf[:])
			if err != nil {
				fmt.Printf("Create failed: %s\n", err)
				os.Exit(1)
			}

		case auth.KEY_TOKEN_SIGNATURE_KEY:
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Printf("ed25519.GenerateKey: %s\n", err)
				os.Exit(1)
			}

			err = params.secretManager.Create(auth.KEY_TOKEN_SIGNATURE_KEY,
				priv)
			if err != nil {
				fmt.Printf("Create failed: %s\n", err)
				os.Exit(1)
			}
			_, err = params.store.NewAsset(auth.ASSET_AUTH_PUBKEY, pub)
			if err != nil {
				fmt.Printf("Failed to store public key: %s\n", err)
				os.Exit(1)
			}

		default:
			fmt.Printf("Unknown key type %s\n", arg)
			os.Exit(1)
		}
	}

	return nil
}

func keyGet(params keyParams, args []string) error {
	if len(args) == 0 {
		fmt.Printf("Usage: key get TYPE...\nWhere typs is:\n")
		fmt.Printf(" - %s\tOAuth2 Client ID secret\n",
			auth.KEY_CLIENT_ID_SECRET)
		fmt.Printf(" - %s\tToken signature keypair\n",
			auth.KEY_TOKEN_SIGNATURE_KEY)
		return nil
	}

	for _, arg := range args {
		switch arg {
		case auth.KEY_CLIENT_ID_SECRET:
			data, err := params.secretManager.Get(auth.KEY_CLIENT_ID_SECRET, "")
			if err != nil {
				fmt.Printf("Get failed: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("Data:\n%s", hex.Dump(data))

		default:
			fmt.Printf("Unknown key type %s\n", arg)
			os.Exit(1)
		}
	}

	return nil
}
