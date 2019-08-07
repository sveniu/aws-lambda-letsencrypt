package s3

import (
	"bytes"
	"encoding/pem"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/mitchellh/mapstructure"

	"github.com/sveniu/aws-lambda-letsencrypt/export"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

type S3Config struct {
	Region      string `mapstructure:"region"`
	Bucket      string `mapstructure:"bucket"`
	Prefix      string `mapstructure:"prefix"`
	SSEKMSKeyID string `mapstructure:"sse_kms_key_id"`
}

var backendConfig *S3Config

func init() {
	export.RegisterBackend("aws-s3", func() (export.Backend, error) {
		return &S3ExporterBackend{}, nil
	})
}

type S3ExporterBackend struct {
	Name string
}

// FIXME: Move the config into the 'b' structure itself?
func (b *S3ExporterBackend) Configure(
	configData map[string]interface{},
) error {
	backendConfig = new(S3Config)
	if err := mapstructure.Decode(configData, &backendConfig); err != nil {
		return err
	}

	return nil
}

func (b *S3ExporterBackend) Export(
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

	svc := s3.New(sess, aws.NewConfig().WithRegion(backendConfig.Region))

	// Store the result files to the target S3 bucket and prefix.
	for _, f := range []struct {
		Key       string
		PEMType   string
		DataBlobs [][]byte
	}{
		{
			backendConfig.Prefix + "privatekey.pem",
			"RSA PRIVATE KEY",
			[][]byte{privKeyBytes},
		},
		{
			backendConfig.Prefix + "certificate.pem",
			"CERTIFICATE",
			[][]byte{certBytes},
		},
		{
			backendConfig.Prefix + "cabundle.pem",
			"CERTIFICATE",
			cabundleBytes,
		},
	} {
		bodyBytes := new(bytes.Buffer)
		for _, c := range f.DataBlobs {
			pem.Encode(bodyBytes, &pem.Block{Type: f.PEMType, Bytes: c})
		}
		bodyReader := bytes.NewReader(bodyBytes.Bytes())
		poParams := &s3.PutObjectInput{
			Body:   bodyReader,
			Bucket: &backendConfig.Bucket,
			Key:    &f.Key,
		}
		if backendConfig.SSEKMSKeyID != "" {
			poParams = poParams.SetServerSideEncryption("aws:kms")
			poParams = poParams.SetSSEKMSKeyId(backendConfig.SSEKMSKeyID)
		}
		_, err = svc.PutObject(poParams)
		if err != nil {
			log.Error(
				"Error calling PutObject",
				rz.Err(err),
				rz.String("s3_bucket", backendConfig.Bucket),
				rz.String("s3_key", f.Key),
			)
			return err
		}
	}

	return nil
}
