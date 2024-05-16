package main

// handler test: run the entire handler with mocks for the expensive
// CA issuance call and its direct downstream consumer.

// TODO - remove secretsmanager mock.

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockPCAClient is a mock of the PCA client, so this runs
// without the non-free-tier awspca.
type MockPCAClient struct {
	mock.Mock
}

func (m *MockPCAClient) IssueCertificate(ctx context.Context, params *acmpca.IssueCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*acmpca.IssueCertificateOutput), args.Error(1)
}

func (m *MockPCAClient) GetCertificate(ctx context.Context, params *acmpca.GetCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*acmpca.GetCertificateOutput), args.Error(1)
}

// MockSecretsManagerClient is a mock of the Secrets Manager client
type MockSecretsManagerClient struct {
	mock.Mock
}

func (m *MockSecretsManagerClient) CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*secretsmanager.CreateSecretOutput), args.Error(1)
}

func TestHandleRequest(t *testing.T) {
	ctx := context.Background()

	// Only the private CA client is mocked, since it's expensive.
	mockPCAClient := new(MockPCAClient)

	// Setup expectations
	arnInput := "arn:aws:acm-pca:us-west-2:000000000000:certificate/00000000-0000-0000-0000-000000000000"
	arnOutput := "arn:aws:acm-pca:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012"

	mockPCAClient.On("IssueCertificate", ctx, mock.AnythingOfType("*acmpca.IssueCertificateInput")).Return(&acmpca.IssueCertificateOutput{
		CertificateArn: aws.String(arnOutput),
	}, nil)

	mockPCAClient.On("GetCertificate", ctx, mock.AnythingOfType("*acmpca.GetCertificateInput")).Return(&acmpca.GetCertificateOutput{
		Certificate: aws.String("dummy-certificate"),
	}, nil)

	// Done with the mock; now for the real objects.
	// Get the real AWS SDK config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	assert.NoError(t, err)

	handler := &Handler{
		AwsConfig:         cfg,
		AwsPCA:            mockPCAClient,
		AwsSecretsManager: secretsmanager.NewFromConfig(cfg),
		AwsPCAConfig: PCAConfig{
			CaArn:            arnInput,
			SigningAlgorithm: DefaultSigningAlgorithm,
			ValidityDays:     365,
			RsaKeySize:       2048,
		},
	}

	// Call the handler
	result, err := handler.HandleLambda(ctx, EventDetail{"example.com", []string{"www.example.com"}})
	assert.NoError(t, err)
	assert.Equal(t, arnOutput, result)

	// Assert that the expectations were met
	mockPCAClient.AssertExpectations(t)
}
