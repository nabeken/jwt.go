package jwt

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pmylund/go-cache"
	"github.com/square/go-jose"
)

// JWKSet represents JWK Set.
// See https://tools.ietf.org/html/rfc7517#section-5
type JWKSet struct {
	Keys []*jose.JsonWebKey `json:"keys"`
}

// JWKSetResponse represents a response of JWK Set.
// This contains a TTL (Time to Live) for caching purpose.
type JWKSetResponse struct {
	Keys []*jose.JsonWebKey

	TTL time.Duration // This would be used as TTL for caching.
}

// JWKsFetcher is an interface that represents JWKs fetcher.
type JWKsFetcher interface {
	// FetchJWKs retrieves JWKSet from path.
	FetchJWKs(path string) (*JWKSetResponse, error)
}

// JWKsHTTPFetcher fetches JWKs via HTTP.
type JWKsHTTPFetcher struct {
	Client *http.Client
}

// FetchJWKs implements JWKsFetcher interface by using http.Client.
// FetchJWKs tries to retrieve JWKSet from uri.
func (f *JWKsHTTPFetcher) FetchJWKs(uri string) (*JWKSetResponse, error) {
	resp, err := f.Client.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jwks, err := DecodeJWKSet(resp.Body)
	return &JWKSetResponse{
		Keys: jwks,
	}, err
}

// JWKsS3Fetcher fetches JWKs via S3.
type JWKsS3Fetcher struct {
	S3Svc s3iface.S3API
}

// FetchJWKs implements JWKsS3Fetcher by using S3. It tries to retrieve an S3 object from path.
// path must be in s3://<bucket>/<key>.
func (f *JWKsS3Fetcher) FetchJWKs(path string) (*JWKSetResponse, error) {
	s3url, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	params := &s3.GetObjectInput{
		Bucket: aws.String(s3url.Host),
		Key:    aws.String(s3url.Path),
	}
	resp, err := f.S3Svc.GetObject(params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jwks, err := DecodeJWKSet(resp.Body)
	return &JWKSetResponse{
		Keys: jwks,
	}, err
}

// JWKsCacher fetches JWKs via Cache if available.
type JWKsCacher struct {
	fetcher JWKsFetcher
	cache   *cache.Cache

	defaultExpiration time.Duration
	cleanupInterval   time.Duration
}

// NewCacher returns JWKsCacher with initializing cache store.
func NewCacher(defaultExpiration, cleanupInterval time.Duration, f JWKsFetcher) *JWKsCacher {
	c := cache.New(defaultExpiration, cleanupInterval)
	return &JWKsCacher{
		fetcher: f,
		cache:   c,

		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
	}
}

// FetchJWKs tries to retrieve JWKs from Cache. If the cache is not available,
// it will call Fetcher.FetchJWKs and cache the result for future request.
func (c *JWKsCacher) FetchJWKs(cacheKey string) (*JWKSetResponse, error) {
	if keys, found := c.cache.Get(cacheKey); found {
		return &JWKSetResponse{Keys: keys.([]*jose.JsonWebKey)}, nil
	}
	jwksresp, err := c.fetcher.FetchJWKs(cacheKey)
	if err != nil {
		return nil, err
	}

	ttl := jwksresp.TTL

	// If TTL is larger than cleanupInterval, we should subtract cleanupInterval from TTL to
	// make sure that the latest jwks is obtained.
	if ttl > c.cleanupInterval {
		ttl -= c.cleanupInterval
	}

	c.cache.Set(cacheKey, jwksresp.Keys, ttl)
	return jwksresp, nil
}

// DecodeJWKSet decodes the data with reading from r into JWKs.
func DecodeJWKSet(r io.Reader) ([]*jose.JsonWebKey, error) {
	keyset := JWKSet{}
	if err := json.NewDecoder(r).Decode(&keyset); err != nil && err != io.EOF {
		return nil, err
	}

	return keyset.Keys, nil
}
