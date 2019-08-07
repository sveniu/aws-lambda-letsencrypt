package letsencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

const minRsaKeyBits = 2048

func GenerateCSR(
	keyBits int,
	dnsNames []string,
) (
	[]byte,
	*rsa.PrivateKey,
	error,
) {
	if keyBits < minRsaKeyBits {
		return nil, nil, fmt.Errorf("Key bits %d < %d", keyBits, minRsaKeyBits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, err
	}

	csrTemplate := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dnsNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(
		rand.Reader,
		&csrTemplate,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	return csrBytes, privateKey, nil
}

func VerifyChain(
	c *x509.Certificate,
	der [][]byte,
	dnsName string,
) error {
	certPool := x509.NewCertPool()
	for _, certBytes := range der {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return err
		}
		certPool.AddCert(cert)
	}
	log.Debug(
		"Got certificate pool",
		rz.Any("certificate_pool", certPool),
	)

	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: certPool,
	}
	chains, err := c.Verify(opts)
	if err != nil {
		return err
	}

	log.Debug(
		"Certificate chains",
		rz.Any("chains", chains),
	)

	return nil
}
