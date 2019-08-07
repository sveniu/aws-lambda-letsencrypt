package certstore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

const (
	fnCertConfig  = "certconfig.yaml"
	fnPrivateKey  = "privatekey.pem"
	fnCertificate = "certificate.pem"
	fnCABundle    = "cabundle.pem"

	defaultRSAKeyBits               = 2048
	defaultValidityDurationSeconds  = 60 * 60 * 24 * 90 // 90 days
	defaultBeforeValidityEndSeconds = 60 * 60 * 24 * 10 // 10 days
)

type CertificateStore struct {
	Service       *s3.S3
	S3Region      string
	S3Bucket      string
	S3Prefix      string
	S3SSEKMSKeyID string
}

func parseCertificateConfig(
	certConfigBytes []byte,
) (
	*CertificateConfig,
	error,
) {
	var certConfig CertificateConfig
	if err := yaml.Unmarshal(certConfigBytes, &certConfig); err != nil {
		log.Error(
			"Error unmarshalling certificate configuration YAML",
			rz.Err(err),
			rz.Bytes("input_bytes", certConfigBytes),
		)
		return nil, err
	}
	log.Debug(
		"Got unmarshalled certificate configuration",
		rz.Any("certificate_configuration", certConfig),
	)

	// Set defaults.
	if certConfig.CertSpec.KeyBits == 0 {
		certConfig.CertSpec.KeyBits = defaultRSAKeyBits
	}
	if certConfig.CertSpec.ValidityDuration == 0 {
		certConfig.CertSpec.ValidityDuration = defaultValidityDurationSeconds
	}
	if certConfig.Renewal.BeforeValidityEnd == 0 {
		certConfig.Renewal.BeforeValidityEnd = defaultBeforeValidityEndSeconds
	}

	return &certConfig, nil
}

func New(
	s3Region string,
	s3Bucket string,
	s3Prefix string,
	s3SSEKMSKeyID string,
) (
	*CertificateStore,
	error,
) {
	sess, err := session.NewSession()
	if err != nil {
		log.Error(
			"Error starting AWS session",
			rz.Err(err),
		)
		return nil, err
	}

	svc := s3.New(sess, aws.NewConfig().WithRegion(s3Region))

	return &CertificateStore{
		Service:       svc,
		S3Region:      s3Region,
		S3Bucket:      s3Bucket,
		S3Prefix:      s3Prefix,
		S3SSEKMSKeyID: s3SSEKMSKeyID,
	}, nil
}

func (cs *CertificateStore) needsRenewal(
	certConfig *CertificateConfig,
) bool {
	key := certConfig.S3Prefix + "/" + fnCertificate
	goParams := &s3.GetObjectInput{
		Bucket: &cs.S3Bucket,
		Key:    &key,
	}

	log.Info(
		"Checking certificate renewal status",
		rz.String("s3_bucket", cs.S3Bucket),
		rz.String("s3_key", key),
		rz.Any("certificate_configuration", certConfig),
	)

	goOutput, err := cs.Service.GetObject(goParams)
	if err != nil {
		log.Warn(
			"Error calling GetObject",
			rz.Err(err),
			rz.Any("parameters", goParams),
		)
		return true
	}

	objectBytes, err := ioutil.ReadAll(goOutput.Body)
	if err != nil {
		log.Warn(
			"Error reading response body",
			rz.Err(err),
			rz.Any("parameters", goParams),
		)
		return true
	}

	pemBlock, _ := pem.Decode(objectBytes)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		log.Warn(
			"Error decoding PEM",
			rz.Bytes("input_bytes", objectBytes),
		)
		return true
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Warn(
			"Error parsing certificate",
			rz.Err(err),
			rz.Bytes("input_bytes", pemBlock.Bytes),
		)
		return true
	}

	log.Debug(
		"Certificate time details",
		rz.Time("valid_not_before", cert.NotBefore),
		rz.Time("valid_not_after", cert.NotAfter),
		rz.Time("time_now", time.Now()),
		rz.Int64("renew_before_validity_end",
			certConfig.Renewal.BeforeValidityEnd),
	)

	// FIXME separate function for unit testing
	var renewAfter time.Time
	if certConfig.Renewal.BeforeValidityEnd > 0 {
		renewAfter = cert.NotAfter.Add(
			-1 * time.Second *
				time.Duration(certConfig.Renewal.BeforeValidityEnd),
		)
		if time.Now().After(renewAfter) {
			log.Info(
				"Renewal needed",
				rz.Int64("before_validity_end",
					certConfig.Renewal.BeforeValidityEnd),
			)
			return true
		}
	}

	log.Debug("No renewal needed")

	return false
}

func (cs *CertificateStore) Scan() (
	[]*CertificateConfig,
	error,
) {
	lov2Params := &s3.ListObjectsV2Input{
		Bucket: &cs.S3Bucket,
		Prefix: &cs.S3Prefix,
	}

	var certConfigs []*CertificateConfig

	log.Debug(
		"Scanning for certificate configurations",
		rz.String("operation", "S3.ListObjectsV2Pages"),
		rz.Any("arguments", lov2Params),
	)
	err := cs.Service.ListObjectsV2Pages(lov2Params,
		func(page *s3.ListObjectsV2Output, lastPage bool) bool {
			for _, object := range page.Contents {
				// Check filename.
				fn := (*object.Key)[strings.LastIndex(*object.Key, "/")+1:]
				if fn != fnCertConfig {
					log.Debug(
						"Skipping object",
						rz.String("reason", "Filename mismatch"),
						rz.String("expected_filename", fnCertConfig),
						rz.String("s3_bucket", *lov2Params.Bucket),
						rz.String("s3_key", *object.Key),
					)
					continue
				}

				// Check size.
				if *object.Size <= 0 {
					log.Debug(
						"Skipping object",
						rz.String("reason", "Size is zero"),
						rz.String("s3_bucket", *lov2Params.Bucket),
						rz.String("s3_key", *object.Key),
					)
					continue
				}

				// Fetch cert spec file.
				certConfig, err := cs.Get(*lov2Params.Bucket, *object.Key)
				if err != nil {
					log.Debug(
						"Skipping object",
						rz.String("reason", "Error from certificate store"),
						rz.Err(err),
						rz.String("s3_bucket", *lov2Params.Bucket),
						rz.String("s3_key", *object.Key),
					)
					continue
				}

				if certConfig == nil {
					log.Debug(
						"Skipping object",
						rz.String("reason", "Uneligible certificate"),
						rz.String("s3_bucket", *lov2Params.Bucket),
						rz.String("s3_key", *object.Key),
					)
					continue
				}

				certConfigs = append(certConfigs, certConfig)
			}

			return false
		})
	if err != nil {
		log.Error(
			"Error calling ListObjectsV2Pages",
			rz.Err(err),
		)
		return nil, err
	}

	return certConfigs, nil
}

// Get returns a certificate configuration matching the specified S3 bucket and
// object key.
func (cs *CertificateStore) Get(
	bucket string,
	key string,
) (
	*CertificateConfig,
	error,
) {
	goParams := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	goOutput, err := cs.Service.GetObject(goParams)
	if err != nil {
		log.Warn(
			"Error calling GetObject",
			rz.Err(err),
			rz.Any("parameters", goParams),
		)
		return nil, err
	}

	objectBytes, err := ioutil.ReadAll(goOutput.Body)
	if err != nil {
		log.Warn(
			"Error reading response body",
			rz.Err(err),
			rz.Any("parameters", goParams),
		)
		return nil, err
	}

	certConfig, err := parseCertificateConfig(objectBytes)
	if err != nil {
		log.Warn(
			"Error parsing certificate configuration",
			rz.Err(err),
			rz.Bytes("input_bytes", objectBytes),
		)
		return nil, err
	}

	log.Debug(
		"Got certificate configuration",
		rz.Any("certificate_configuration", certConfig),
	)

	// Set the S3 prefix.
	certConfig.S3Prefix = key[:strings.LastIndex(key, "/")]

	if !cs.needsRenewal(certConfig) {
		log.Debug(
			"Certificate does not need renewal",
			rz.Any("certificate_configuration", certConfig),
		)
		return nil, nil
	}

	return certConfig, nil
}

func (cs *CertificateStore) saveAsPEM(
	key string,
	pemType string,
	dataBlobs [][]byte,
) error {
	bodyBytes := new(bytes.Buffer)
	for _, b := range dataBlobs {
		if err := pem.Encode(
			bodyBytes,
			&pem.Block{
				Type:  pemType,
				Bytes: b,
			}); err != nil {
			log.Error(
				"Error encoming PEM",
				rz.Err(err),
			)
			return err
		}
	}
	bodyReader := bytes.NewReader(bodyBytes.Bytes())
	poParams := &s3.PutObjectInput{
		Body:   bodyReader,
		Bucket: &cs.S3Bucket,
		Key:    &key,
	}

	if cs.S3SSEKMSKeyID != "" {
		log.Debug(
			"KMS key specified; using S3 server-side encryption",
			rz.String("kms_key_id", cs.S3SSEKMSKeyID),
			rz.Any("parameters", poParams),
		)
		poParams = poParams.SetServerSideEncryption("aws:kms")
		poParams = poParams.SetSSEKMSKeyId(cs.S3SSEKMSKeyID)
	} else {
		log.Debug(
			"KMS key not specified; not using S3 server-side encryption",
			rz.Any("parameters", poParams),
		)
	}

	if _, err := cs.Service.PutObject(poParams); err != nil {
		log.Debug(
			"Error calling PutObject",
			rz.Err(err),
			rz.String("s3_bucket", cs.S3Bucket),
			rz.String("s3_key", key),
		)
		return err
	}

	return nil
}

func (cs *CertificateStore) SaveCertificate(
	prefix string,
	privKey []byte,
	cert []byte,
	cabundle [][]byte,
) error {
	for _, f := range []struct {
		Key       string
		PEMType   string
		DataBlobs [][]byte
	}{
		{
			prefix + "/" + fnPrivateKey,
			"RSA PRIVATE KEY",
			[][]byte{privKey},
		},
		{
			prefix + "/" + fnCertificate,
			"CERTIFICATE",
			[][]byte{cert},
		},
		{
			prefix + "/" + fnCABundle,
			"CERTIFICATE",
			cabundle,
		},
	} {
		if err := cs.saveAsPEM(f.Key, f.PEMType, f.DataBlobs); err != nil {
			log.Debug(
				"Error saving PEM",
				rz.Err(err),
				rz.String("pem_type", f.PEMType),
				rz.String("s3_key", f.Key),
			)
			return err
		}
	}

	return nil
}

func (cs *CertificateStore) String() string {
	return "<certstore:S3:" +
		cs.S3Region + ":" +
		cs.S3Bucket + "/" +
		cs.S3Prefix + ">"
}
