package backends

import (
	// initialise all backends.
	_ "github.com/sveniu/aws-lambda-letsencrypt/export/backends/aws-acm"
	_ "github.com/sveniu/aws-lambda-letsencrypt/export/backends/aws-s3"
	_ "github.com/sveniu/aws-lambda-letsencrypt/export/backends/aws-sns"
)
