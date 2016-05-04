package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/onopm/go-httpscert"
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: https-cert url\n")
		flag.PrintDefaults()
	}
}

func main() {
	var (
		insecure bool
	)
	flag.BoolVar(&insecure, "k", false, "don't validate the certificate")
	flag.BoolVar(&insecure, "insecure", false, "don't validate the certificate")
	flag.Parse()

	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	conf := httpscert.Config{
		Insecure: insecure,
		Url:      flag.Args()[0],
	}

	err := httpscert.Run(conf)
	if err != nil {
		os.Exit(1)
	}

}
