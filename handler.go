package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// PCAClient defines the interface we use for the ACM PCA client
type PCAClient interface {
	IssueCertificate(ctx context.Context, params *acmpca.IssueCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error)
	GetCertificate(ctx context.Context, params *acmpca.GetCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error)
}

// SecretsManagerClient defines the interface we use for the Secrets Manager client
type SecretsManagerClient interface {
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
}

// Handler is the main struct for the Lambda handler, giving me testability.
type Handler struct {
	AwsConfig         config.Config
	AwsPCA            PCAClient
	AwsSecretsManager SecretsManagerClient
	AwsPCAConfig      PCAConfig
}

// The contents of the request (the only parameters the user can change in
// the issued certificate).
type EventDetail struct {
	Subject_cn        string   `json:"subject_cn"`
	Alternative_names []string `json:"alternative_names"`
}

// Common configurations that this service will apply to all certificates.
type PCAConfig struct {
	// The ARN provided by AWS's private CA service.
	CaArn string
	// Information about the signing algorithm - see details below.
	SigningAlgorithm SigningAlgorithmConfig
	// The number of days the certificate will be valid for.
	ValidityDays int64
	// The size of the RSA key to generate in bits, e.g. 2048.
	RsaKeySize int
}

// Group signing constants together, both MUST refer to the same algorithm
// but by historical accident they are named differently. Currently may only
// be RSA.
type SigningAlgorithmConfig struct {
	PCAAlgorithm  types.SigningAlgorithm
	X509Algorithm x509.SignatureAlgorithm
}

var (
	// This is actually a const, but Go doesn't allow const structs.
	DefaultSigningAlgorithm = SigningAlgorithmConfig{
		PCAAlgorithm:  types.SigningAlgorithmSha256withrsa,
		X509Algorithm: x509.SHA256WithRSA,
	}
)

// The format of a certificate as stored in the secret manager.
// All fields are PEM-encoded.
type StorableKey struct {
	PrivateKey  string `json:"private_key"`
	Certificate string `json:"certificate"`
	// Cetificate chain, stored as concatenated PEM-encoded certificates (as usual).
	Chain string `json:"chain"`
}

// The ARN of the issued certificate, usable to fetch the key from the secrets manager.
type Response struct {
	CertSMARN string `json:"cert_sm_arn"`
}

// GenerateCSR generates a Certificate Signing Request (CSR).
func (h Handler) GenerateCSR(privateKey crypto.PrivateKey, subjectCN string, alternativeNames []string) ([]byte, error) {
	// Fill in the fields of the CSR.
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subjectCN,
		},
		DNSNames:           alternativeNames,
		SignatureAlgorithm: h.AwsPCAConfig.SigningAlgorithm.X509Algorithm,
	}

	// Generate the secure CSR.
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}

	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csrPem, nil
}

func (h Handler) GeneratePrivateKey() (*rsa.PrivateKey, error) {
	// Uses Go 1.22's new cryptographic randomness API.
	privateKey, err := rsa.GenerateKey(rand.Reader, h.AwsPCAConfig.RsaKeySize)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (h Handler) MarshalKey(privateKey *rsa.PrivateKey, cert, certChain string) (StorableKey, error) {
	// Marshal the private key.
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// The certificate and chain are already in PEM format.
	return StorableKey{
		PrivateKey:  string(privateKeyPem),
		Certificate: cert,
		Chain:       certChain,
	}, nil
}

// Call the certificate authority - note that this call costs
// money, about a nickel per call for individual use on the
// (mostly) free tier.
func (h Handler) IssueCertificate(ctx context.Context, csr []byte) (*acmpca.IssueCertificateOutput, error) {
	req := &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: &h.AwsPCAConfig.CaArn,
		Csr:                     csr,
		SigningAlgorithm:        h.AwsPCAConfig.SigningAlgorithm.PCAAlgorithm,
		Validity: &types.Validity{
			Type:  types.ValidityPeriodTypeDays,
			Value: &h.AwsPCAConfig.ValidityDays,
		},
	}

	arn, err := h.AwsPCA.IssueCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	return arn, err
}

func (h Handler) GetCertificate(ctx context.Context, arn string) (*acmpca.GetCertificateOutput, error) {
	req := &acmpca.GetCertificateInput{
		CertificateArn:          &arn,
		CertificateAuthorityArn: &h.AwsPCAConfig.CaArn,
	}

	cert, err := h.AwsPCA.GetCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func (h *Handler) StoreCertificateInSecretsManager(ctx context.Context, secretName string, key StorableKey) (*string, error) {
	client := h.AwsSecretsManager

	secretValueJson, err := json.Marshal(key)
	if err != nil {
		log.Printf("failed to marshal secret value: %v", err)
		return nil, err
	}

	cso, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String(string(secretValueJson)),
	})
	if err != nil {
		return nil, err
	} else {
		log.Printf("created secret with ARN: %s", *cso.ARN)
		return cso.ARN, nil
	}
}

func (h Handler) HandleLambda(ctx context.Context, event EventDetail) (*Response, error) {
	log.Printf("Handler invoked with the following event: %s", event)

	// Generate a private key.
	privateKey, err := h.GeneratePrivateKey()
	if err != nil {
		log.Printf("failed to generate new private key: %v", err)
		return nil, err
	}

	// Prepare the CSR.
	csr, err := h.GenerateCSR(privateKey, event.Subject_cn, event.Alternative_names)
	if err != nil {
		log.Printf("failed to prepare CSR: %v", err)
		return nil, err
	}

	// Issue the certificate.
	resp, err := h.IssueCertificate(ctx, csr)
	if err != nil {
		log.Printf("failed to issue certificate: %v", err)
		return nil, err
	}

	// Gather the issued certificate information.
	cert, err := h.GetCertificate(ctx, *resp.CertificateArn)
	if err != nil {
		log.Printf("failed to retrieve issued certificate: %v", err)
		return nil, err
	}

	// Build formatted certificate information for storage.
	key, err := h.MarshalKey(privateKey, *cert.Certificate, *cert.CertificateChain)
	if err != nil {
		log.Printf("failed to marshal certificate information into storage format: %v", err)
		return nil, err
	}

	// Store the cert information into the secrets manager.
	secretID := "certificate-" + event.Subject_cn // TODO - don't know what to do
	arn, err := h.StoreCertificateInSecretsManager(ctx, secretID, key)
	if err != nil {
		log.Printf("failed to store certificate secrets: %v", err)
		return nil, err
	}

	log.Printf("certificate stored in secrets manager with ARN: %s", *arn)
	log.Printf("certificate stored in secrets manager with ARN: %s", *arn)

	r := &Response{
		CertSMARN: *arn,
	}
	return r, nil
}
