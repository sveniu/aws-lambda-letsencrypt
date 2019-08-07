package acm

import (
	"bytes"
	"encoding/pem"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"

	"github.com/mitchellh/mapstructure"

	"github.com/sveniu/aws-lambda-letsencrypt/export"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

type ACMConfig struct {
	Region         string `mapstructure:"region"`
	CertificateArn string `mapstructure:"certificate_arn"`
}

var backendConfig *ACMConfig

func init() {
	export.RegisterBackend("aws-acm", func() (export.Backend, error) {
		return &ACMExporterBackend{}, nil
	})
}

type ACMExporterBackend struct {
	Name string
}

// FIXME: Move the config into the 'b' structure itself?
func (b *ACMExporterBackend) Configure(
	configData map[string]interface{},
) error {
	backendConfig = new(ACMConfig)
	if err := mapstructure.Decode(configData, &backendConfig); err != nil {
		return err
	}

	return nil
}

func (b *ACMExporterBackend) Export(
	privKeyBytes []byte,
	certBytes []byte,
	cabundleBytes [][]byte,
) error {
	sess, err := session.NewSession()
	if err != nil {
		log.Error(
			"Error starting AWS session",
			rz.Err(err),
		)
		return err
	}

	svc := acm.New(sess, aws.NewConfig().WithRegion(backendConfig.Region))

	// Private key.
	pkBytes := new(bytes.Buffer)
	pem.Encode(pkBytes, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes})

	// Main cert.
	mainCertBytes := new(bytes.Buffer)
	pem.Encode(mainCertBytes, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// CA bundle.
	caBundleBytes := new(bytes.Buffer)
	for _, c := range cabundleBytes {
		pem.Encode(caBundleBytes, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}

	icParams := &acm.ImportCertificateInput{
		Certificate:      mainCertBytes.Bytes(),
		CertificateArn:   &backendConfig.CertificateArn,
		CertificateChain: caBundleBytes.Bytes(),
		PrivateKey:       pkBytes.Bytes(),
	}

	log.Debug(
		"Calling ACM.ImportCertificate",
		rz.Any("parameters", icParams),
	)
	if _, err := svc.ImportCertificate(icParams); err != nil {
		log.Error(
			"Error calling ACM.ImportCertificate",
			rz.Err(err),
		)
		return err
	}

	return nil
}
