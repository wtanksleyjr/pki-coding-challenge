package f9_pki_coding_challenge

import (
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	h := Handler{}
	lambda.Start(h.Handler)
}
