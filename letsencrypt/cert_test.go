package letsencrypt

import (
	"crypto/x509"
	"testing"
)

type generateCSRTestCase struct {
	keyBits     int
	dnsNames    []string
	expectedErr bool
}

var generateCSRTestCases = []generateCSRTestCase{
	generateCSRTestCase{
		keyBits:     1,
		dnsNames:    []string{"example.com"},
		expectedErr: true,
	},
	generateCSRTestCase{
		keyBits:     2047,
		dnsNames:    []string{"example.com"},
		expectedErr: true,
	},
	generateCSRTestCase{
		keyBits:     2048,
		dnsNames:    []string{"example.com"},
		expectedErr: false,
	},
	generateCSRTestCase{
		keyBits:     2049,
		dnsNames:    []string{"example.com"},
		expectedErr: false,
	},
	generateCSRTestCase{
		keyBits:     2048,
		dnsNames:    []string{"example.com", "example.net"},
		expectedErr: false,
	},
	generateCSRTestCase{
		keyBits:     2048,
		dnsNames:    []string{},
		expectedErr: false,
	},
}

func TestGenerateCSR(
	t *testing.T,
) {
	for _, tc := range generateCSRTestCases {
		_, _, err := GenerateCSR(tc.keyBits, tc.dnsNames)
		if err != nil {
			if !tc.expectedErr {
				t.Errorf("Unexpected error: Args (%v, %v) -> %v",
					tc.keyBits, tc.dnsNames, err)
			}
		} else {
			if tc.expectedErr {
				t.Errorf(
					"Unexpected success: Args (%v, %v)",
					tc.keyBits,
					tc.dnsNames,
				)
			}
		}
	}

	inputKeyBits := 2048
	inputDnsNames := []string{"example.com", "example.net"}

	var csrBytes []byte

	// Verify CSR.
	csrBytes, _, err := GenerateCSR(inputKeyBits, inputDnsNames)
	if err != nil {
		t.Error(err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Error(err)
	}

	if csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("Unexpected signature algo: %+v", csr.SignatureAlgorithm)
	}

	if len(csr.EmailAddresses) != 0 {
		t.Errorf("Unexpected email addresses: %+v", csr.EmailAddresses)
	}

	if len(csr.IPAddresses) != 0 {
		t.Errorf("Unexpected IP addresses: %+v", csr.IPAddresses)
	}

	if len(csr.DNSNames) != len(inputDnsNames) {
		t.Errorf(
			"Mismatching length of DNS names: Wanted %d, got %d",
			len(inputDnsNames),
			len(csr.DNSNames),
		)
	}

	for index, dnsName := range csr.DNSNames {
		if dnsName != inputDnsNames[index] {
			t.Errorf(
				"Mismatching DNS name: Wanted %s, got %s",
				inputDnsNames[index],
				dnsName,
			)
		}
	}
}
