package f9_pki_coding_challenge

import (
	"context"
	"log"
)

type Handler struct {
	// TODO: Add here any dependencies the handler may have.
	//   - Consider using interfaces for upstream dependencies to enable better unit testing
}

type EventDetail struct {
	// TODO: Add here supported/expected inputs when lambda is invoked
}

type Response struct {
	CertSMARN string `json:"cert_sm_arn"`
}

func (h Handler) Handler(ctx context.Context, event EventDetail) (*Response, error) {
	log.Printf("Handler invoked with the following event:%s\n", event)
	// TODO: Populate this function and add other functions as needed to support the functionality required in the problem statement
	r := &Response{}
	return r, nil
}
