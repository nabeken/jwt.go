package jwt

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/square/go-jose"
)

// JWKSet represents JWK Set.
// See https://tools.ietf.org/html/rfc7517#section-5
type JWKSet struct {
	Keys []*jose.JsonWebKey `json:"keys"`
}

// JWKsFetcher is an interface that represents JWKs fetcher.
type JWKsFetcher interface {
	FetchJWKs(string) ([]*jose.JsonWebKey, error)
}

// JWKsHTTPFetcher fetches JWKs via HTTP.
type JWKsHTTPFetcher struct {
	Client http.Client
}

// FetchJWKs implements JWKsFetcher interface.
func (f *JWKsHTTPFetcher) FetchJWKs(uri string) ([]*jose.JsonWebKey, error) {
	resp, err := f.Client.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	keyset := JWKSet{}
	if err := json.NewDecoder(resp.Body).Decode(&keyset); err != nil && err != io.EOF {
		return nil, err
	}

	return keyset.Keys, nil
}

// VerifyJWKs validates jws by jwks and return the payload.
// If VerifyJWKs fails to validate by all jwks, it will return the last verification error.
func VerifyJWKs(jws *jose.JsonWebSignature, jwks []*jose.JsonWebKey) ([]byte, error) {
	var err error
	for _, jwk := range jwks {
		if rawJWT, err := jws.Verify(jwk); err == nil {
			return rawJWT, nil
		}
	}
	return nil, err
}
