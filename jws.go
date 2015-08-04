package jwt

import "github.com/square/go-jose"

// VerifyJWS validates jws by jwks and return the jwk and payload.
// If VerifyJWS fails to validate by all jwks, it will return the last verification error.
func VerifyJWS(jws *jose.JsonWebSignature, jwks []*jose.JsonWebKey) ([]byte, *jose.JsonWebKey, error) {
	var err error
	for _, jwk := range jwks {
		if rawJWT, err := jws.Verify(jwk); err == nil {
			return rawJWT, jwk, nil
		}
	}
	return nil, nil, err
}
