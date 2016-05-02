package httpscert

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

const location = "Asia/Tokyo"

func commonName(cert *x509.Certificate) string {
	for i := 0; i < len(cert.Subject.Names); i++ {
		v := cert.Subject.Names[i]
		if v.Type.Equal(oidCN) {
			return v.Value.(string)
		}
	}
	return ""
}

func printCert(cert *x509.Certificate, prefix string) {
	//TODO: use template

	loc, _ := time.LoadLocation(location)

	fmt.Printf("%sversion: %d\n", prefix, cert.Version)
	fmt.Printf("%sserial number: %s\n", prefix, cert.SerialNumber)

	fmt.Printf("%sSignatureAlgorithm: %v\n", prefix, cert.SignatureAlgorithm)

	for i := 0; i < len(cert.Issuer.Names); i++ {
		v := cert.Issuer.Names[i]
		fmt.Printf("%sIssuer %v(%v):%v\n", prefix, oidName(v.Type), v.Type, v.Value)
	}

	fmt.Printf("%sValidity Not Before: %v\n", prefix, cert.NotBefore.In(loc))
	fmt.Printf("%sValidity Not After:  %v\n", prefix, cert.NotAfter.In(loc))

	for i := 0; i < len(cert.Subject.Names); i++ {
		v := cert.Subject.Names[i]
		fmt.Printf("%sSubject %v(%v):%v\n", prefix, oidName(v.Type), v.Type, v.Value)
	}

	//TODO.
	//fmt.Printf("PublicKeyAlgorithm: %v\n", cert.PublicKeyAlgorithm)
}

var (
	oidCN    = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidC     = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidL     = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidO     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOU    = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidEMail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

func oidName(oi asn1.ObjectIdentifier) string {
	switch {
	case oi.Equal(oidCN):
		return "commonName"
	case oi.Equal(oidC):
		return "countryName"
	case oi.Equal(oidL):
		return "localityName"
	case oi.Equal(oidO):
		return "organizationName"
	case oi.Equal(oidOU):
		return "organizationalUnitName"
	case oi.Equal(oidEMail):
		return "email"
	default:
		return "OID unknown"
	}
}
