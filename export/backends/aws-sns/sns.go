package sns

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"

	"github.com/mitchellh/mapstructure"

	"github.com/sveniu/aws-lambda-letsencrypt/export"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

type SNSConfig struct {
	Region   string `mapstructure:"region"`
	TopicArn string `mapstructure:"topic_arn"`
}

var backendConfig *SNSConfig

func init() {
	export.RegisterBackend("aws-sns", func() (export.Backend, error) {
		return &SNSExporterBackend{}, nil
	})
}

type SNSExporterBackend struct {
	Name string
}

// FIXME: Move the config into the 'b' structure itself?
func (b *SNSExporterBackend) Configure(
	configData map[string]interface{},
) error {
	backendConfig = new(SNSConfig)
	if err := mapstructure.Decode(configData, &backendConfig); err != nil {
		return err
	}

	return nil
}

func (b *SNSExporterBackend) Export(
	_ []byte,
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

	subject, message, err := makeSubjectAndBody(certBytes, cabundleBytes)
	if err != nil {
		log.Error(
			"Error making subject or body",
			rz.Err(err),
		)
		return err
	}

	svc := sns.New(sess, aws.NewConfig().WithRegion(backendConfig.Region))

	pParams := &sns.PublishInput{
		Message:  &message,
		Subject:  &subject,
		TopicArn: &backendConfig.TopicArn,
	}

	log.Debug(
		"Calling SNS.Publish",
		rz.Any("parameters", pParams),
	)
	pOutput, err := svc.Publish(pParams)
	if err != nil {
		log.Error(
			"Error calling SNS.Publish",
			rz.Err(err),
		)
		return err
	}

	log.Info(
		"Published SNS message",
		rz.Any("parameters", pParams),
		rz.String("sns_message_id", *pOutput.MessageId),
	)

	return nil
}
