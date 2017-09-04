package jwkset

// Fetcher is an interface that represents JWKs fetcher.
type Fetcher interface {
	// FetchJWKs retrieves JWKSet from path.
	FetchJWKs(path string) (*JWKSetResponse, error)
}
