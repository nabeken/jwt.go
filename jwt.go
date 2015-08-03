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

// JWKFetcher is an interface that represents JWK fetcher.
type JWKFetcher interface {
	FetchJWK() ([]*jose.JsonWebKey, error)
}

// NewJWKFetcher returns JWKFetcher that fetches JWKs from uri.
func NewJWKFetcher(uri string) JWKFetcher {
	return &jwkFetcher{
		uri: uri,
	}
}

type jwkFetcher struct {
	uri string
}

// FetchJWK implements JWKFetcher interface.
func (f *jwkFetcher) FetchJWK() ([]*jose.JsonWebKey, error) {
	resp, err := http.Get(f.uri)
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
