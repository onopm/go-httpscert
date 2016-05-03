package httpscert

import (
	"fmt"
	"net/http"
)

func Run(url string) error {

	infof("http get: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("http handle error %s", err)
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		infof("connection CipherSuite: %s", tlsCipherSuite(resp.TLS.CipherSuite))
		infof("connection TLS Version: %s", tlsVersion(resp.TLS.Version))

		for i := 0; i < len(resp.TLS.PeerCertificates); i++ {
			infof("cert[%d]: %s", i, commonName(resp.TLS.PeerCertificates[i]))
			printCert(resp.TLS.PeerCertificates[i], fmt.Sprintf("  cert[%d]", i))
		}
	} else {
		warnf("not found TLS information.")
	}

	return nil
}
