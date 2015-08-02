package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWKFetcher(t *testing.T) {
	assert := assert.New(t)
	fetcher := &JWKFetcher{
		URI: "https://www.googleapis.com/oauth2/v3/certs",
	}

	jwks, err := fetcher.FetchJWK()
	assert.NoError(err)
	assert.Len(jwks, 2)
}
