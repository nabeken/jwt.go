package jwkset

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/patrickmn/go-cache"
	"gopkg.in/square/go-jose.v2"
)

// JWKSetResponse represents a response of JWK Set.
// This contains a TTL (Time to Live) for caching purpose.
type JWKSetResponse struct {
	Keys []jose.JSONWebKey

	TTL time.Duration // This would be used as TTL for caching.
}

// HTTPFetcher fetches JWKs over HTTP.
type HTTPFetcher struct {
	Client *http.Client
}

// FetchJWKs implements Fetcher interface by using http.Client.
// FetchJWKs tries to retrieve JWKSet from uri.
func (f *HTTPFetcher) FetchJWKs(uri string) (*JWKSetResponse, error) {
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

// S3Fetcher fetches JWKs via S3.
type S3Fetcher struct {
	S3Svc s3iface.S3API
}

// FetchJWKs implements JWKsS3Fetcher by using S3. It tries to retrieve an S3 object from path.
// path must be in s3://<bucket>/<key>.
func (f *S3Fetcher) FetchJWKs(path string) (*JWKSetResponse, error) {
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

// Cacher fetches JWKs via Cache if available.
type Cacher struct {
	fetcher JWKsFetcher
	cache   *cache.Cache

	defaultExpiration time.Duration
	cleanupInterval   time.Duration
}

// NewCacher returns Cacher with initializing cache store.
func NewCacher(defaultExpiration, cleanupInterval time.Duration, f JWKsFetcher) *Cacher {
	c := cache.New(defaultExpiration, cleanupInterval)
	return &Cacher{
		fetcher: f,
		cache:   c,

		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
	}
}

// FetchJWKs tries to retrieve JWKs from Cache. If the cache is not available,
// it will call Fetcher.FetchJWKs and cache the result for future request.
func (c *Cacher) FetchJWKs(cacheKey string) (*JWKSetResponse, error) {
	if keys, found := c.cache.Get(cacheKey); found {
		return &JWKSetResponse{Keys: keys.([]jose.JSONWebKey)}, nil
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
func DecodeJWKSet(r io.Reader) ([]jose.JSONWebKey, error) {
	keyset := jose.JSONWebKeySet{}
	if err := json.NewDecoder(r).Decode(&keyset); err != nil && err != io.EOF {
		return nil, err
	}

	return keyset.Keys, nil
}
