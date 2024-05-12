# f9-pki-coding-challenge

## Context

Our clients are looking for a managed PKI solution whereby they can request private certificates and fully delegate key 
generation and signing to the managed service. Users only provide the details of the cert as input (eg: subject common name, alternative names) 
and the managed PKI service takes that info and generates the private key, signs the cert with the corresponding private CA and stores 
the produced crypto assets (private key, signed cert, chain) in Secrets Manager. Once the cert is provisioned, the end user can 
fetch their cert and private key from Secrets Manager and install it wherever they please.

## Problem Statement

Develop a lambda in Go lang that given the following event input formatted in JSON:

````
{ "subject_cn":"mytest-service.internal", "alternative_names":["mytest-service.internal", "api.mytest-service.internal"]}
````

When that lambda is invoked generates a private cert, CSR and performs an AWS PCA API call to the issue-certificate endpoint 
for signing the cert. Finally, it stores the private key, signed cert and chain in a new secret in AWS Secret Manager (created on the fly). 
The lambda should output the SM ARN where the secret is located following this JSON format:

````
{ "cert_sm_arn":"arn:<aws_partition>:secretsmanager:<aws_region>:<aws_account_id>:secret:<path_to_cert_secret>"}
````

The secret value content must be a JSON with the following format:

````
{
"private_key":"-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
"certificate":"-----BEGIN CERTIFICATE-----\n....\n-----END CERTIFICATE-----",
"chain":"-----BEGIN CERTIFICATE-----\n.....\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n.....\n-----END CERTIFICATE-----"
}
````

Where private key is RSA (eg: 2,048 size) in PEM format, certificate is a bundled x509 cert in PEM format (containing the 
end entity cert plus all the intermediate CAs in the chain), and the chain contains all the CA certs (Intermediate CAs and 
ROOT CA inclusive).

## Considerations

- We are not expecting the candidate to provision any real infrastructure in AWS as part of this exercise.
- The lambda should make use of the AWS Go SDK to interact with the required services (eg: AWS PCA, AWS SecretsManager, etc)
  - The `Handler` should leverage interfaces for its dependencies so different implementations can be provided. For instance, 
the main.go could set up the Handler struct with real AWS SDK service implementations; while the unit tests could set up the 
Handler with stub implementations.
  - The candidate is free to pick whichever AWS SDK GO version implementation is preferable:
  -  [aws-sdk-go](https://github.com/aws/aws-sdk-go)
  -  [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2)
- We value clean code that is readable, well organized and testable.
- This exercise is intended to be completed within 3 hours (and 4 hours including the nice to have).

## Deliverables

### Must haves

- Solution is checked into a private repo in GitHub that we can get access to.
- The lambda meets the above requirements and produces the expected output.
- The lambda logs show the secret value that was pushed to Secret Manager. This is needed so we can assess that the value pushed comply with the specs mentioned above)
- Code is tested with proper coverage. All unit test pass  successfully:

````
go test ./...
ok      f9-pki-coding-challenge 0.345s
````

### Nice to have

- The lambda runs within a docker image that can be executed locally (ref: https://docs.aws.amazon.com/lambda/latest/dg/go-image.html)

````
$ curl "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{"common_name":"mytest-service.internal", "alternative_names":["mytest-service.internal"]}'
{ "cert_sm_arn":"arn:aws:secretsmanager:us-west-2:1234567:secret:<path_to_cert_secret>"}
````

