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
	"fmt"
	"os"

	"github.com/markkurossi/auth"
	"golang.org/x/crypto/ed25519"
)

func cmdKey(store *auth.ClientStore) {
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
