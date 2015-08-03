package main

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
