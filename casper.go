package main

import (
	"fmt"
)

func main() {
	certs, ok := getKeyring("")
	if ok != nil {
		panic("problem loading keyring")
	}

	for _, cert := range certs {
		fmt.Println(cert)
		for _, sk := range cert.Subkeys {
			fmt.Printf("\t%s\n", sk)
			for _, v := range sk.Signatures {
				fmt.Printf("\t\t%s\n", v[len(v)-1])
			}
		}
		for _, uid := range cert.Uids {
			fmt.Printf("\t%s\n", uid)
			for _, v := range uid.Signatures {
				fmt.Printf("\t\t%s\n", v[len(v)-1])
			}
		}
	}
}
