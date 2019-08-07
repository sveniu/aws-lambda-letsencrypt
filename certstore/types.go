package certstore

type CertificateSpec struct {
	KeyBits          int      `yaml:"key_bits"`
	DNSNames         []string `yaml:"dns_names"`
	ValidityDuration int64    `yaml:"validity_duration_seconds"`
	SkipVerifyChain  bool     `yaml:"skip_verify_chain"`
}

// FIXME: Put fields into CertificateSpec instead?
type RenewalConfig struct {
	BeforeValidityEnd int64 `yaml:"before_validity_end_seconds"`
}

type Validator struct {
	Type          string                 `yaml:"type"`
	ChallengeType string                 `yaml:"challenge_type"`
	Config        map[string]interface{} `yaml:"config"`
}

type Exporter struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config"`
}

type CertificateConfig struct {
	S3Prefix   string
	CertSpec   *CertificateSpec `yaml:"certificate_spec"`
	Renewal    *RenewalConfig   `yaml:"renewal"`
	Validators []*Validator
	Exporters  []*Exporter
}
