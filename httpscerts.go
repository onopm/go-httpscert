package httpscert

import (
	"fmt"
	"log"
	"net/http"
)

func Run(url string) error {

	log.Printf("http get: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("http handle error %s", err)
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		log.Printf("connection CipherSuite: %s", tlsCipherSuite(resp.TLS.CipherSuite))
		log.Printf("connection TLS Version: %s", tlsVersion(resp.TLS.Version))

		for i := 0; i < len(resp.TLS.PeerCertificates); i++ {

			log.Printf("cert[%d]: %s", i, commonName(resp.TLS.PeerCertificates[i]))
			printCert(resp.TLS.PeerCertificates[i], fmt.Sprintf("  cert[%d]", i))
		}
	} else {
		log.Println("not found TLS information.")
	}

	return nil
}
