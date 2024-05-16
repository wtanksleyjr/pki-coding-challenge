package main

// component tests: check individual functions from the handler that require
// no or minimal mocking.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

func TestMarshalKey(t *testing.T) {
	InitDefaults(context.Background())
	handler := DefaultHandler

	key, err := handler.GeneratePrivateKey()
	assert.NoError(t, err)

	// Marshal the key
	storable, err := handler.MarshalKey(key, "fakecert", "fakecertchain")
	assert.NoError(t, err)

	// Decode the PEM block
	block, _ := pem.Decode([]byte(storable.PrivateKey))
	assert.NotNil(t, block)
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)

	// Unmarshal the key
	unmarshalledKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Compare the keys
	assert.Equal(t, key, unmarshalledKey)
}

func TestGenerateCSR(t *testing.T) {
	InitDefaults(context.Background())
	handler := DefaultHandler

	key, err := handler.GeneratePrivateKey()
	assert.NoError(t, err)

	csr, err := handler.GenerateCSR(key, "example.com", []string{"www.example.com"})
	assert.NoError(t, err)

	// Decode the PEM block
	block, _ := pem.Decode(csr)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
}

func TestStoreCertificate(t *testing.T) {
	ctx := context.Background()
	InitDefaults(ctx)
	handler := DefaultHandler

	secretID := "testarnfake"
	stored := StorableKey{
		PrivateKey:  "testfakekey",
		Certificate: "testfakecert",
		Chain:       "tastfakechain",
	}

	t.Cleanup(func() {
		var immediate int64 = 0
		_, err := handler.AwsSecretsManager.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String(secretID),
			RecoveryWindowInDays: &immediate,
		})
		assert.NoError(t, err)
	})

	_, err := handler.StoreCertificateInSecretsManager(ctx, secretID, stored)
	assert.NoError(t, err)

	// Check that the secret exists
	so, err := handler.AwsSecretsManager.GetSecretValue(ctx,
		&secretsmanager.GetSecretValueInput{
			SecretId: &secretID,
		})
	assert.NoError(t, err)
	assert.NotNil(t, so)
	assert.NotNil(t, so.SecretString)

	fetched := StorableKey{}
	assert.NoError(t, json.Unmarshal([]byte(*so.SecretString), &fetched))
	assert.Equal(t, stored, fetched)
}
