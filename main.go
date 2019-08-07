package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/sveniu/aws-lambda-letsencrypt/certstore"
	"github.com/sveniu/aws-lambda-letsencrypt/export"
	_ "github.com/sveniu/aws-lambda-letsencrypt/export/backends"
	"github.com/sveniu/aws-lambda-letsencrypt/letsencrypt"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

var (
	clientKeyEncrypted     string
	accountId              string
	acmeBaseURL            string
	certstoreS3Region      string
	certstoreS3Bucket      string
	certstoreS3Prefix      string
	certstoreS3SSEKMSKeyID string
)

const (
	defaultLogLevel = rz.InfoLevel
)

func init() {
	var ok bool

	clientKeyEncrypted, ok = os.LookupEnv("ACME_CLIENT_KEY")
	if !ok {
		panic("Environment variable 'ACME_CLIENT_KEY' not set")
	}

	accountId, ok = os.LookupEnv("ACME_ACCOUNT_ID")
	if !ok {
		panic("Environment variable 'ACME_ACCOUNT_ID' not set")
	}

	acmeBaseURL, ok = os.LookupEnv("ACME_BASE_URL")
	if !ok {
		panic("Environment variable 'ACME_BASE_URL' not set")
	}

	certstoreS3Region, ok = os.LookupEnv("CERTSTORE_S3_REGION")
	if !ok {
		panic("Environment variable 'CERTSTORE_S3_REGION' not set")
	}

	certstoreS3Bucket, ok = os.LookupEnv("CERTSTORE_S3_BUCKET")
	if !ok {
		panic("Environment variable 'CERTSTORE_S3_BUCKET' not set")
	}

	certstoreS3Prefix, ok = os.LookupEnv("CERTSTORE_S3_PREFIX")
	if !ok {
		panic("Environment variable 'CERTSTORE_S3_PREFIX' not set")
	}

	certstoreS3SSEKMSKeyID, ok = os.LookupEnv("CERTSTORE_S3_SSE_KMS_KEY_ID")
	if !ok {
		panic("Environment variable 'CERTSTORE_S3_SSE_KMS_KEY_ID' not set")
	}
}

func decryptKmsData(
	encrypted string,
) (
	[]byte,
	error,
) {
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return []byte{}, err
	}

	sess, err := session.NewSession()
	if err != nil {
		log.Error(
			"Error starting AWS session",
			rz.Err(err),
		)
		return nil, err
	}

	svc := kms.New(sess)
	input := &kms.DecryptInput{
		CiphertextBlob: decoded,
	}
	result, err := svc.Decrypt(input)
	if err != nil {
		return []byte{}, err
	}

	return result.Plaintext, nil
}

func getClientKey() (
	crypto.Signer,
	error,
) {
	clientKeyHex, err := decryptKmsData(clientKeyEncrypted)
	if err != nil {
		return nil, err
	}

	clientKeyBytes, err := hex.DecodeString(string(clientKeyHex))
	if err != nil {
		return nil, err
	}

	clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBytes)
	if err != nil {
		return nil, err
	}

	return clientKey, nil
}

// FIXME return error?
func exportResult(
	certConfig *certstore.CertificateConfig,
	res *letsencrypt.LECertResult,
) {
	for _, exporter := range certConfig.Exporters {
		log.Debug(
			"Attempting exporter",
			rz.String("exporter_type", exporter.Type),
			rz.Any("exporter", exporter),
		)
		eb, err := export.InitBackend(exporter.Type)
		if err != nil {
			log.Warn(
				"Error initializing exporter backend",
				rz.Err(err),
				rz.Any("exporter", exporter),
			)
			continue
		}

		if err := eb.Configure(exporter.Config); err != nil {
			log.Warn(
				"Error configuring exporter backend",
				rz.Err(err),
				rz.Any("exporter", exporter),
			)
			continue
		}

		if err := eb.Export(
			res.PrivateKey,
			res.Certificate,
			res.CABundle,
		); err != nil {
			log.Warn(
				"Error during export",
				rz.Err(err),
				rz.Any("exporter", exporter),
			)
			continue
		}
	}
}

func handleS3Event(
	ctx context.Context,
	evt events.S3Event,
) (
	interface{},
	error,
) {
	cs, err := certstore.New(
		certstoreS3Region,
		certstoreS3Bucket,
		certstoreS3Prefix,
		certstoreS3SSEKMSKeyID,
	)
	if err != nil {
		log.Error(
			"Error initalizing certificate store",
			rz.Err(err),
			rz.String("s3_region", certstoreS3Region),
			rz.String("s3_bucket", certstoreS3Bucket),
			rz.String("s3_prefix", certstoreS3Prefix),
			rz.String("s3_sse_kms_key_id", certstoreS3SSEKMSKeyID),
		)
		return nil, err
	}

	var certConfigs []*certstore.CertificateConfig
	for _, rec := range evt.Records {
		log.Debug(
			"Got S3 event record",
			rz.Any("s3_event_record", rec),
		)
		certConfig, err := cs.Get(rec.S3.Bucket.Name, rec.S3.Object.Key)
		if err != nil {
			log.Warn(
				"Error fetching certificate configuration",
				rz.Err(err),
				rz.String("s3_bucket", rec.S3.Bucket.Name),
				rz.String("s3_key", rec.S3.Object.Key),
			)
			return nil, err
		}
		if certConfig == nil {
			log.Info(
				"Skipping uneligible certificate or file",
				rz.String("s3_bucket", rec.S3.Bucket.Name),
				rz.String("s3_key", rec.S3.Object.Key),
			)
			return nil, nil
		}
		log.Info(
			"Adding eligible certificate",
			rz.Any("certificate_configuration", certConfig),
		)
		certConfigs = append(certConfigs, certConfig)
	}

	log.Debug(
		"Got certificate configurations",
		rz.Any("certificate_configurations", certConfigs),
	)

	// Decrypt and fetch the Let's Encrypt client key.
	clientKey, err := getClientKey()
	if err != nil {
		log.Error(
			"Error getting Let's Encrypt client key",
			rz.Err(err),
		)
		return nil, err
	}

	// Initialize Let's Encrypt.
	lesvc := letsencrypt.New(clientKey, accountId, acmeBaseURL)

	// Iterate over certificates.
	for _, certConfig := range certConfigs {
		log.Debug(
			"Requesting (re)new certificate",
			rz.Any("certificate_configuration", certConfig),
		)
		res, err := lesvc.DoCertificate(ctx, certConfig)
		if err != nil {
			log.Warn(
				"Error requesting certificate",
				rz.Err(err),
			)
			continue // FIXME or bail?
		}

		if err := cs.SaveCertificate(
			certConfig.S3Prefix,
			res.PrivateKey,
			res.Certificate,
			res.CABundle,
		); err != nil {
			log.Warn(
				"Error saving certificate",
				rz.Err(err),
				rz.String("s3_prefix", certConfig.S3Prefix),
			)
			continue // FIXME or bail?
		}

		exportResult(certConfig, res)
	}

	return nil, nil
}

func handleScheduledEvent(
	ctx context.Context,
	evt events.CloudWatchEvent,
) (
	interface{},
	error,
) {
	cs, err := certstore.New(
		certstoreS3Region,
		certstoreS3Bucket,
		certstoreS3Prefix,
		certstoreS3SSEKMSKeyID,
	)
	if err != nil {
		log.Error(
			"Error initalizing certificate store",
			rz.Err(err),
			rz.String("s3_region", certstoreS3Region),
			rz.String("s3_bucket", certstoreS3Bucket),
			rz.String("s3_prefix", certstoreS3Prefix),
			rz.String("s3_sse_kms_key_id", certstoreS3SSEKMSKeyID),
		)
		return nil, err
	}

	certConfigs, err := cs.Scan()
	if err != nil {
		log.Error(
			"Error scanning certificate store",
			rz.Err(err),
			rz.Any("certificate_store", cs),
		)
		return nil, err
	}

	log.Debug(
		"Got certificate store",
		rz.Any("certificate_configurations", certConfigs),
	)

	if len(certConfigs) < 1 {
		log.Info(
			"No eligible certificate configuration found",
			rz.Any("certificate_configurations", certConfigs),
		)
		return nil, nil
	}

	// Decrypt and fetch the Let's Encrypt client key.
	clientKey, err := getClientKey()
	if err != nil {
		log.Error(
			"Error getting Let's Encrypt client key",
			rz.Err(err),
		)
		return nil, err
	}

	// Initialize Let's Encrypt.
	lesvc := letsencrypt.New(clientKey, accountId, acmeBaseURL)

	// Iterate over certificates.
	for _, certConfig := range certConfigs {
		log.Debug(
			"Requesting (re)new certificate",
			rz.Any("certificate_configuration", certConfig),
		)
		res, err := lesvc.DoCertificate(ctx, certConfig)
		if err != nil {
			log.Warn(
				"Error requesting certificate",
				rz.Err(err),
			)
			continue // FIXME or bail?
		}

		if err := cs.SaveCertificate(
			certConfig.S3Prefix,
			res.PrivateKey,
			res.Certificate,
			res.CABundle,
		); err != nil {
			log.Warn(
				"Error saving certificate",
				rz.Err(err),
				rz.String("s3_prefix", certConfig.S3Prefix),
			)
			continue // FIXME or bail?
		}

		exportResult(certConfig, res)
	}

	return nil, nil
}

func handler(
	ctx context.Context,
	evt json.RawMessage,
) (
	interface{},
	error,
) {
	var err error
	var res interface{}
	var s3Event events.S3Event

	err = json.Unmarshal(evt, &s3Event)
	if err == nil {
		if len(s3Event.Records) > 0 && s3Event.Records[0].EventSource == "aws:s3" {
			res, err = handleS3Event(ctx, s3Event)
			if err != nil {
				log.Error(
					"Error handling S3 event",
					rz.Err(err),
					rz.Any("s3_event", s3Event),
				)
				return nil, err
			}
			log.Debug(
				"Successfully handled S3 event",
				rz.Any("s3_event", s3Event),
			)
			return res, nil
		}
	}
	log.Debug(
		"Error unmarshalling event as S3 event",
		rz.Err(err),
		rz.Any("event", evt),
	)

	var cwsEvent events.CloudWatchEvent
	err = json.Unmarshal(evt, &cwsEvent)
	if err == nil {
		if cwsEvent.Source == "aws.events" {
			res, err = handleScheduledEvent(ctx, cwsEvent)
			if err != nil {
				log.Error(
					"Error handling CloudWatch scheduled event",
					rz.Err(err),
					rz.Any("cws_event", cwsEvent),
				)
				return nil, err
			}
			log.Debug(
				"Successfully handled CloudWatch scheduled event",
				rz.Any("cws_event", cwsEvent),
			)
			return res, nil
		}
	}
	log.Debug(
		"Error unmarshalling event as CloudWatch scheduled event",
		rz.Err(err),
		rz.Any("event", evt),
	)

	return nil, err
}

func main() {
	log.SetLogger(log.With(
		rz.Level(defaultLogLevel),
		rz.Fields(
			rz.Timestamp(true),
			rz.Stack(true),
			rz.Caller(true),
		),
	))

	// Set log level based on LOG_LEVEL environment variable.
	if logLevelString, ok := os.LookupEnv("LOG_LEVEL"); ok {
		if logLevel, err := rz.ParseLevel(logLevelString); err == nil {
			log.SetLogger(log.With(
				rz.Level(logLevel),
			))
		} else {
			log.Info(
				"Failed to parse log level string",
				rz.String("input_log_level_string", logLevelString),
				rz.String("environment_variable", "LOG_LEVEL"),
				rz.String("current_log_level", defaultLogLevel.String()),
			)
		}
	}

	lambda.Start(handler)
}
