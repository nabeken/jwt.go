package jwt

import (
	"net/http"
	"testing"
	"time"

	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
)

func TestJWKsFetcher(t *testing.T) {
	assert := assert.New(t)
	fetcher := &JWKsHTTPFetcher{
		Client: &http.Client{},
	}
	jwksresp, err := fetcher.FetchJWKs("https://www.googleapis.com/oauth2/v3/certs")
	assert.NoError(err)
	assert.Len(jwksresp.Keys, 2)
}

func TestJWKsCacher(t *testing.T) {
	defaultExpiration := 10 * time.Minute
	cleanupInterval := time.Minute

	assert := assert.New(t)
	cacher := NewCacher(defaultExpiration, cleanupInterval, &JWKsHTTPFetcher{
		Client: &http.Client{},
	})

	cacheKey := "https://www.googleapis.com/oauth2/v3/certs"
	jwksresp, err := cacher.FetchJWKs(cacheKey)
	assert.NoError(err)
	assert.Len(jwksresp.Keys, 2)

	cachedResp, found := cacher.cache.Get(cacheKey)
	assert.True(found)

	resp, ok := cachedResp.([]*jose.JsonWebKey)
	if assert.True(ok, "cached response should be []*jose.JsonWebKey but %#v", cachedResp) {
		assert.Equal(jwksresp.Keys, resp)
	}

	jwksresp, err = cacher.FetchJWKs(cacheKey)
	assert.NoError(err)
	assert.Len(jwksresp.Keys, 2)
}
