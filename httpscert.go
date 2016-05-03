package httpscert

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func Run(url string) error {

	infof("http get: %s", url)

	infof("set InsecureSkipVerify: true")
	//not set TLS.VerifiedChains.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         0,
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		critf("http handle error: %s", err)
		return fmt.Errorf("http get error")
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		infof("connection CipherSuite: %s", tlsCipherSuite(resp.TLS.CipherSuite))
		infof("connection TLS Version: %s", tlsVersion(resp.TLS.Version))

		for i := 0; i < len(resp.TLS.PeerCertificates); i++ {
			infof("cert[%d]: %s", i, resp.TLS.PeerCertificates[i].Subject.CommonName)

			if i == 0 {
				err := resp.TLS.PeerCertificates[i].VerifyHostname(resp.Request.URL.Host)
				if err != nil {
					warnf("cert[%d]: %s", i, err)
				}

			}

			printCert(resp.TLS.PeerCertificates[i], fmt.Sprintf("  cert[%d]", i))

		}
	} else {
		warnf("not found TLS information.")
	}

	return nil
}
