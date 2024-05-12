package f9_pki_coding_challenge

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHandleRequest(t *testing.T) {
	h := Handler{}
	response, err := h.Handler(context.TODO(), EventDetail{})
	expectedResponse := &Response{}
	assert.Nil(t, err)
	assert.Equal(t, expectedResponse, response)
}

// TODO: Add more unit tests here as needed
