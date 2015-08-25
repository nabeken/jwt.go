package jwt

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWKFetcher(t *testing.T) {
	assert := assert.New(t)
	fetcher := &JWKsHTTPFetcher{
		Client: &http.Client{},
	}
	jwksresp, err := fetcher.FetchJWKs("https://www.googleapis.com/oauth2/v3/certs")
	assert.NoError(err)
	assert.Len(jwksresp.Keys, 2)
}
