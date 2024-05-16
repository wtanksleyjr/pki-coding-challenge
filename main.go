package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var DefaultHandler *Handler

func InitDefaults(ctx context.Context) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
		return
	}
	DefaultHandler = &Handler{
		AwsConfig:         cfg,
		AwsPCA:            acmpca.NewFromConfig(cfg),
		AwsSecretsManager: secretsmanager.NewFromConfig(cfg),
		AwsPCAConfig: PCAConfig{
			CaArn:            "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012",
			SigningAlgorithm: DefaultSigningAlgorithm,
			ValidityDays:     365,
			RsaKeySize:       2048,
		},
	}

}

// Gather configs and start the AWS Lambda handler.
func main() {
	ctx := context.Background()
	InitDefaults(ctx)

	lambda.Start(DefaultHandler.HandleLambda)
}
