package main

import (
	//"fmt"
	"github.com/google/nftables"
	"log"
	"os"
)

const (
	version		float32	=	0.1
)

var (
	connNft		*nftables.Conn
	err		error
)

func main() {
	log.Println("Starting charcoal", version, ", establishing connection to nftables")
	connNft, err = nftables.New()
	if err != nil {
		log.Fatalln("Could not establish connection to nftables: " + err.Error())
	}
	log.Println("Established connection")
}