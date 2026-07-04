package main

import (
	"fmt"
	"io"
	"os"

	"github.com/TKYcraft/amane/internal/keys"
)

func runGenkey() error {
	k, err := keys.GeneratePrivateKey()
	if err != nil {
		return err
	}
	fmt.Println(k.String())
	return nil
}

func runPubkey() error {
	in, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	if err != nil {
		return err
	}
	k, err := keys.Parse(string(in))
	if err != nil {
		return err
	}
	fmt.Println(keys.PublicKey(k).String())
	return nil
}
