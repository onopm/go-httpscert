package main

import (
	"fmt"
	"log"
	"os"

	"github.com/onopm/go-httpscert"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: https-cert url")
		os.Exit(1)
	}
	url := os.Args[1]

	err := httpscert.Run(url)
	if err != nil {
		log.Println(err)
	}
}
