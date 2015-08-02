package jwt

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/square/go-jose"
)

// See https://tools.ietf.org/html/rfc7517#section-5
type JWKSet struct {
	Keys []*jose.JsonWebKey `json:"keys"`
}

type JWKFetcher struct {
	URI string
}

func (f *JWKFetcher) FetchJWK() ([]*jose.JsonWebKey, error) {
	resp, err := http.Get(f.URI)
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
