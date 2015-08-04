package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// OAuth2TokenResponse represents a response from OAuth2 token endpoint.
type OAuth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpireIn    int64  `json:"expire_in"`
	IDToken     string `json:"id_token"`
}

type OIDCClaimSet struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Email string `json:"email"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// StateToken returns securely-generated random string. It is suitable for state parameter.
func StateToken() string {
	randBuf := make([]byte, 30)
	rand.Read(randBuf)
	hasher := sha256.New()
	hasher.Sum(randBuf)
	return hex.EncodeToString(hasher.Sum(nil))
}
