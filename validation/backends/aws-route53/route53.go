package route53

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"

	"github.com/sveniu/aws-lambda-letsencrypt/validation"

	"golang.org/x/crypto/acme"

	"github.com/mitchellh/mapstructure"

	"gitlab.com/z0mbie42/rz-go/v2"
	"gitlab.com/z0mbie42/rz-go/v2/log"
)

type Route53Config struct {
	ZoneId  string `mapstructure:"zone_id"`
	RoleArn string `mapstructure:"role_arn"`
}

var backendConfig *Route53Config

func init() {
	validation.RegisterBackend("aws-route53", func() (validation.Backend, error) {
		return &Route53ValidatorBackend{}, nil
	})
}

type Route53ValidatorBackend struct {
	Name string
}

func isEqualResourceRecordSet(
	a *route53.ResourceRecordSet,
	b *route53.ResourceRecordSet,
) bool {
	// Any nil pointer will be interpreted as a mismatch.
	if a.Name == nil || b.Name == nil {
		return false
	}
	if a.Type == nil || b.Type == nil {
		return false
	}
	if a.TTL == nil || b.TTL == nil {
		return false
	}

	// Compare simple fields.
	if *a.Name != *b.Name {
		return false
	}
	if *a.Type != *b.Type {
		return false
	}
	if *a.TTL != *b.TTL {
		return false
	}
	if len(a.ResourceRecords) != len(b.ResourceRecords) {
		return false
	}

	// Compare resource records (assume sorted).
	for i, _ := range a.ResourceRecords {
		if *a.ResourceRecords[i].Value != *b.ResourceRecords[i].Value {
			return false
		}
	}

	// The sets match.
	return true
}

func UpsertResourceRecordSet(
	svc *route53.Route53,
	zoneId string,
	rrName string,
	rrType string,
	rrRdata []string,
	rrTTL int64,
) error {
	// Prepare input resource record set.
	inputResourceRecordSet := &route53.ResourceRecordSet{
		Name:            aws.String(rrName),
		ResourceRecords: make([]*route53.ResourceRecord, len(rrRdata)),
		TTL:             aws.Int64(rrTTL),
		Type:            aws.String(route53.RRTypeTxt),
	}

	// Populate resource records.
	for i, rr := range rrRdata {
		inputResourceRecordSet.ResourceRecords[i] = &route53.ResourceRecord{
			Value: aws.String(rr),
		}
	}

	// Check whether the rrset already exists.
	rrsetExists := false
	lrrsParams := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneId),
	}
	log.Debug(
		"Calling Route53.ListResourceRecordSetsPages",
		rz.Any("parameters", lrrsParams),
	)
	err := svc.ListResourceRecordSetsPages(lrrsParams,
		func(page *route53.ListResourceRecordSetsOutput, lastPage bool) bool {
			for _, rrset := range page.ResourceRecordSets {
				if isEqualResourceRecordSet(rrset, inputResourceRecordSet) {
					rrsetExists = true
					return false // Stop page iteration.
				}
			}
			return true // Continue page iteration.
		})
	if err != nil {
		log.Debug(
			"Error calling ListResourceRecordSetsPages",
			rz.Err(err),
		)
		return err
	}

	// Return early if no action is required.
	if rrsetExists {
		log.Debug(
			"Returning early, since a matching rrset was found",
		)
		return nil
	}

	// Upsert rrset.
	crrsParams := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action:            aws.String(route53.ChangeActionUpsert),
					ResourceRecordSet: inputResourceRecordSet,
				},
			},
			Comment: aws.String("Sample update."),
		},
		HostedZoneId: aws.String(zoneId),
	}
	log.Debug(
		"Calling Route53.ChangeResourceRecordSets",
		rz.Any("parameters", crrsParams),
	)
	resp, err := svc.ChangeResourceRecordSets(crrsParams)
	if err != nil {
		log.Debug(
			"Error calling ChangeResourceRecordSets",
			rz.Err(err),
		)
		return err
	}

	params2 := &route53.GetChangeInput{
		Id: resp.ChangeInfo.Id,
	}
	log.Debug(
		"Calling Route53.WaitUntilResourceRecordSetsChanged",
		rz.Any("parameters", params2),
	)
	err = svc.WaitUntilResourceRecordSetsChanged(params2)
	if err != nil {
		log.Debug(
			"Error calling WaitUntilResourceRecordSetsChanged",
			rz.Err(err),
		)
		return err
	}

	return nil
}

// FIXME: Move the config into the 'b' structure itself?
func (b *Route53ValidatorBackend) Configure(
	configData map[string]interface{},
) error {
	backendConfig = new(Route53Config)
	if err := mapstructure.Decode(configData, &backendConfig); err != nil {
		return err
	}
	log.Debug(
		"Decoded backend config",
		rz.Any("input", configData),
		rz.Any("output", backendConfig),
	)

	return nil
}

func (b *Route53ValidatorBackend) ValidateIdentifier(
	acmeClient *acme.Client,
	token string,
	dnsName string,
) error {
	rData, err := acmeClient.DNS01ChallengeRecord(token)
	if err != nil {
		return err
	}

	// Qualify the rname.
	if dnsName[len(dnsName)-1] != byte('.') {
		dnsName = dnsName + "."
	}

	// Enclose rdata value in double quotes.
	if rData[0] != byte('"') {
		rData = "\"" + rData + "\""
	}

	sess, err := session.NewSession()
	if err != nil {
		log.Debug(
			"Error starting AWS session",
			rz.Err(err),
		)
		return err
	}

	var svc *route53.Route53
	if backendConfig.RoleArn != "" {
		log.Debug(
			"Assuming IAM role",
			rz.String("iam_role_arn", backendConfig.RoleArn),
		)
		creds := stscreds.NewCredentials(sess, backendConfig.RoleArn)
		if creds == nil {
			// FIXME this nil test is not good enough: NewCredentials doesn't actually
			// switch roles, but merely prepares the datastructure for it.
			return fmt.Errorf(
				"Could not obtain credentials for role '%s'",
				backendConfig.RoleArn,
			)
		}
		log.Debug(
			"Got role credentials",
			rz.Any("credentials", creds),
		)

		svc = route53.New(sess, &aws.Config{Credentials: creds})
	} else {
		log.Debug(
			"No IAM role provided; not switching",
		)
		svc = route53.New(sess)
	}

	if err := UpsertResourceRecordSet(
		svc,
		backendConfig.ZoneId,
		"_acme-challenge."+dnsName,
		"TXT",
		[]string{rData},
		300,
	); err != nil {
		log.Debug(
			"Error calling UpsertResourceRecordSet",
			rz.Err(err),
		)
		return err
	}

	return nil
}
