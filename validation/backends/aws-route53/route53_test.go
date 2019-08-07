package route53

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
)

type compareRRSetTestCase struct {
	a              *route53.ResourceRecordSet
	b              *route53.ResourceRecordSet
	expectedResult bool
}

var rrval1 string = "foo"
var rrval2 string = "bar"

var compareRRSetTestCases = []compareRRSetTestCase{
	// Equal sets.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		expectedResult: true,
	},

	// Different number of resource records.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
				{Value: &rrval2},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		expectedResult: false,
	},

	// Different name.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b: &route53.ResourceRecordSet{
			Name: aws.String("bar.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		expectedResult: false,
	},

	// Different TTL.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(124),
			Type: aws.String("TXT"),
		},
		expectedResult: false,
	},

	// Different type.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("A"),
		},
		expectedResult: false,
	},

	// Different resource record value.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval2},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		expectedResult: false,
	},

	// Missing (nil) members in b.
	compareRRSetTestCase{
		a: &route53.ResourceRecordSet{
			Name: aws.String("foo.example.com."),
			ResourceRecords: []*route53.ResourceRecord{
				{Value: &rrval1},
			},
			TTL:  aws.Int64(123),
			Type: aws.String("TXT"),
		},
		b:              &route53.ResourceRecordSet{},
		expectedResult: false,
	},

	// Missing (nil) members in a and b.
	compareRRSetTestCase{
		a:              &route53.ResourceRecordSet{},
		b:              &route53.ResourceRecordSet{},
		expectedResult: false,
	},
}

func TestCompareRRSets(
	t *testing.T,
) {
	for _, tc := range compareRRSetTestCases {
		if isEqualResourceRecordSet(tc.a, tc.b) != tc.expectedResult {
			t.Errorf("Unexpected result: Args (%v, %v) -> %v",
				tc.a, tc.b, !tc.expectedResult)
		}
	}
}
