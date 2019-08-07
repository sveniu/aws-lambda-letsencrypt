package sns

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"text/template"
)

type CertificateText struct {
	Subject     string
	Issuer      string
	Serial      string
	DNSNames    string
	NotBefore   string
	NotAfter    string
	CABundleLen int
}

const messageTemplate = `Subject:           {{.Subject}}
Issuer:            {{.Issuer}}
Serial:            {{.Serial}}
DNS names:         {{.DNSNames}}
Not valid before:  {{.NotBefore}}
Not valid after:   {{.NotAfter}}
CA bundle:         {{.CABundleLen}} cert(s)

Download the certificate, CA bundle and key from one of the export targets
defined in your certificate configuration file.
`

func formatSerial(
	serial *big.Int,
) string {
	b := serial.Bytes()
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return string(buf[:len(buf)-1])
}

func makeSubjectAndBody(
	certBytes []byte,
	cabundle [][]byte,
) (
	string,
	string,
	error,
) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return "", "", err
	}

	subject := fmt.Sprintf(
		"Certificate ready: %s",
		strings.Join(cert.DNSNames, ", "),
	)

	notBefore, err := cert.NotBefore.MarshalText()
	if err != nil {
		notBefore = []byte("N/A")
	}

	notAfter, err := cert.NotAfter.MarshalText()
	if err != nil {
		notBefore = []byte("N/A")
	}

	certText := &CertificateText{
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		Serial:      formatSerial(cert.SerialNumber),
		DNSNames:    strings.Join(cert.DNSNames, ", "),
		NotBefore:   string(notBefore),
		NotAfter:    string(notAfter),
		CABundleLen: len(cabundle),
	}

	tmpl, err := template.New("message").Parse(messageTemplate)
	if err != nil {
		return "", "", err
	}

	messageBytes := new(bytes.Buffer)
	if err := tmpl.Execute(messageBytes, certText); err != nil {
		return "", "", err
	}

	return subject, messageBytes.String(), nil
}
