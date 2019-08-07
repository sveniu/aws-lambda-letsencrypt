package letsencrypt

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sveniu/aws-lambda-letsencrypt/certstore"
	"github.com/sveniu/aws-lambda-letsencrypt/validation"
	_ "github.com/sveniu/aws-lambda-letsencrypt/validation/backends"

	"golang.org/x/crypto/acme"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

type LEService struct {
	Client    *acme.Client
	AccountId string
}

type LECertResult struct {
	PrivateKey  []byte
	Certificate []byte
	CABundle    [][]byte
}

func New(
	clientKey crypto.Signer,
	accountId string,
	acmeBaseURL string,
) *LEService {
	return &LEService{
		Client: &acme.Client{
			Key:          clientKey,
			DirectoryURL: acmeBaseURL + "/directory",
		},
		AccountId: accountId,
	}
}

func (s *LEService) DoCertificate(
	ctx context.Context,
	certConfig *certstore.CertificateConfig,
) (
	*LECertResult,
	error,
) {
	for _, dnsName := range certConfig.CertSpec.DNSNames {
		authz, err := s.Client.Authorize(ctx, dnsName)
		if err != nil {
			log.Debug(
				"Error authorizing ACME client",
				rz.Err(err),
			)
			return nil, err
		}
		log.Debug(
			"Got ACME authorization",
			rz.Any("authorization", authz),
		)

		if authz.Status == "valid" {
			log.Debug(
				"Skipping already-authzed DNS name",
				rz.String("dns_name", dnsName),
			)
			continue
		}

		var chal *acme.Challenge

		validationDone := false
	ChallengeLoop:
		for index, c := range authz.Challenges {
			log.Debug(
				"Got ACME challenge",
				rz.Int("index", index),
				rz.Any("challenge", c),
			)
			for _, validator := range certConfig.Validators {
				if validator.ChallengeType != c.Type {
					continue
				}

				log.Debug(
					"Attempting validator",
					rz.String("validator_type", validator.Type),
					rz.Any("validator", validator),
				)
				vb, err := validation.InitBackend(validator.Type)
				if err != nil {
					log.Debug(
						"Error initializing validator",
						rz.Err(err),
					)
					continue
				}

				if err := vb.Configure(validator.Config); err != nil {
					log.Debug(
						"Error configuring validator",
						rz.Err(err),
					)
					continue
				}

				// Validate the identifier.
				if err := vb.ValidateIdentifier(
					s.Client,
					c.Token,
					dnsName,
				); err != nil {
					log.Debug(
						"Error validating identifier",
						rz.Err(err),
						rz.String("dns_name", dnsName),
					)
					continue
				}

				chal = c
				validationDone = true
				break ChallengeLoop
			}
		}

		if !validationDone {
			return nil, fmt.Errorf("No validator found, or all failed")
		}

		log.Debug(
			"Calling s.Client.Accept()",
			rz.Any("parameters", chal),
		)
		chl, err := s.Client.Accept(ctx, chal)
		if err != nil {
			log.Debug(
				"Error accepting challenge",
				rz.Err(err),
				rz.Any("challenge", chl),
			)
			return nil, err
		}
		log.Debug(
			"Accepted challenge",
			rz.Any("challenge", chl),
		)

		log.Debug(
			"Calling s.Client.WaitAuthorization()",
			rz.Any("uri", chal.URI),
		)
		auth2, err := s.Client.WaitAuthorization(ctx, chl.URI)
		if err != nil {
			log.Debug(
				"Error waiting for authorization",
				rz.Err(err),
			)
			return nil, err
		}
		log.Debug(
			"Waited and got authorization",
			rz.Any("authorization", auth2),
		)
	}

	// Generate CSR.
	csrBytes, privKey, err := GenerateCSR(
		certConfig.CertSpec.KeyBits,
		certConfig.CertSpec.DNSNames,
	)
	if err != nil {
		log.Debug(
			"Error generating CSR",
			rz.Err(err),
		)
		return nil, err
	}

	log.Debug(
		"Calling s.Client.CreateCert",
	)
	certs, certUrl, err := s.Client.CreateCert(ctx,
		csrBytes,
		time.Second*time.Duration(certConfig.CertSpec.ValidityDuration),
		true,
	)
	if err != nil {
		log.Debug(
			"Error creating certificate",
			rz.Err(err),
		)
		return nil, err
	}
	log.Debug(
		"Got certificate",
		rz.String("certificate_url", certUrl),
	)

	// The host cert is first.
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		log.Debug(
			"Error parsing certificate",
			rz.Err(err),
		)
		return nil, err
	}
	if err := cert.VerifyHostname(certConfig.CertSpec.DNSNames[0]); err != nil {
		log.Debug(
			"Error verifying certificate hostname",
			rz.Err(err),
		)
		return nil, err
	}

	if !certConfig.CertSpec.SkipVerifyChain && len(certs) > 1 {
		log.Debug("Attempting to verify certificate chain")
		err := VerifyChain(cert, certs[1:], certConfig.CertSpec.DNSNames[0])
		if err != nil {
			log.Debug(
				"Error verifying certificate chain",
				rz.Err(err),
			)
			return nil, err
		}
	}

	return &LECertResult{
		PrivateKey:  x509.MarshalPKCS1PrivateKey(privKey),
		Certificate: certs[0],
		CABundle:    certs[1:],
	}, nil
}
