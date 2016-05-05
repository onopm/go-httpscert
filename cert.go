package httpscert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

const location = "Asia/Tokyo"

func printCert(cert *x509.Certificate, prefix string) {
	//TODO: use template

	loc, _ := time.LoadLocation(location)

	fmt.Printf("%sversion: %d\n", prefix, cert.Version)
	fmt.Printf("%sserial number: %s\n", prefix, cert.SerialNumber)

	fmt.Printf("%sSignatureAlgorithm: %v\n", prefix, cert.SignatureAlgorithm)

	for i := 0; i < len(cert.Issuer.Country); i++ {
		fmt.Printf("%sIssuer Country: %s\n", prefix, cert.Issuer.Country[i])
	}
	for i := 0; i < len(cert.Issuer.Locality); i++ {
		fmt.Printf("%sIssuer Locality: %s\n", prefix, cert.Issuer.Locality[i])
	}
	for i := 0; i < len(cert.Issuer.Organization); i++ {
		fmt.Printf("%sIssuer Organization: %s\n", prefix, cert.Issuer.Organization[i])
	}
	for i := 0; i < len(cert.Issuer.OrganizationalUnit); i++ {
		fmt.Printf("%sIssuer OrganizationUnit: %s\n", prefix, cert.Issuer.OrganizationalUnit[i])
	}
	if len(cert.Issuer.CommonName) > 0 {
		fmt.Printf("%sIssuer CommonName: %s\n", prefix, cert.Issuer.CommonName)
	}
	if len(cert.Issuer.SerialNumber) > 0 {
		fmt.Printf("%sIssuer SerialNumber: %s\n", prefix, cert.Issuer.SerialNumber)
	}

	fmt.Printf("%sValidity Not Before: %v\n", prefix, cert.NotBefore.In(loc))
	fmt.Printf("%sValidity Not After:  %v\n", prefix, cert.NotAfter.In(loc))

	for i := 0; i < len(cert.Subject.Country); i++ {
		fmt.Printf("%sSubject Country: %s\n", prefix, cert.Subject.Country[i])
	}
	for i := 0; i < len(cert.Subject.Locality); i++ {
		fmt.Printf("%sSubject Locality: %s\n", prefix, cert.Subject.Locality[i])
	}
	for i := 0; i < len(cert.Subject.Organization); i++ {
		fmt.Printf("%sSubject Organization: %s\n", prefix, cert.Subject.Organization[i])
	}
	for i := 0; i < len(cert.Subject.OrganizationalUnit); i++ {
		fmt.Printf("%sSubject OrganizationUnit: %s\n", prefix, cert.Subject.OrganizationalUnit[i])
	}
	if len(cert.Subject.CommonName) > 0 {
		fmt.Printf("%sSubject CommonName: %s\n", prefix, cert.Subject.CommonName)
	}
	if len(cert.Subject.SerialNumber) > 0 {
		fmt.Printf("%sSubject SerialNumber: %s\n", prefix, cert.Subject.SerialNumber)
	}
	//TODO.
	//fmt.Printf("PublicKeyAlgorithm: %v\n", cert.PublicKeyAlgorithm)
}

func CheckExpiration(c *x509.Certificate) error {
	now := time.Now()
	duration := c.NotAfter.Sub(now)
	dDay := int(duration.Hours() / 24)

	if duration > 0 {
		infof("certificate[%s] will expire in %v days", c.Subject.CommonName, dDay)
		return nil
	} else {
		return errors.New(fmt.Sprintf("certificate[%s] has expired", c.Subject.CommonName))
	}

	return nil
}
