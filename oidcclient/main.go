package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/nabeken/jwt.go"
	"github.com/square/go-jose"
)

var tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"

type OIDCHandler struct {
	ClientID     string
	ClientSecret string
	JWKSetURL    string

	JWKsFetcher jwt.JWKsFetcher
}

func (h *OIDCHandler) HandleAuth(rw http.ResponseWriter, req *http.Request) {
	v := url.Values{}
	v.Set("client_id", h.ClientID)
	v.Set("response_type", "code")
	v.Set("scope", "openid email")
	v.Set("redirect_uri", "http://oidc.dev:8000/oidc/auth/callback")
	v.Set("state", StateToken())
	fmt.Fprintln(rw, "https://accounts.google.com/o/oauth2/v2/auth?"+v.Encode())
}

func (h *OIDCHandler) HandleCallback(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	fmt.Fprintln(rw, "code:", req.Form.Get("code"))
	fmt.Fprintln(rw, "state:", req.Form.Get("state"))

	v := url.Values{}
	v.Set("client_id", h.ClientID)
	v.Set("client_secret", h.ClientSecret)
	v.Set("code", req.Form.Get("code"))
	v.Set("redirect_uri", "http://oidc.dev:8000/oidc/auth/callback")
	v.Set("grant_type", "authorization_code")

	var err error

	resp, err := http.PostForm(tokenEndpoint, v)
	if err != nil {
		http.Error(rw, "unable to retrieve access token and ID Token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintln(rw, string(body))

	tokenResp := OAuth2TokenResponse{}
	if err := json.Unmarshal(body, &tokenResp); err != nil && err != io.EOF {
		http.Error(rw, "unable to parse token response", http.StatusInternalServerError)
		return
	}

	// Parse JWS and validate
	jwsObject, err := jose.ParseSigned(tokenResp.IDToken)
	if err != nil {
		http.Error(rw, "unable to parse JWS", http.StatusInternalServerError)
		return
	}

	// Retrieve JWKs
	jwks, err := h.JWKsFetcher.FetchJWKs(h.JWKSetURL)
	if err != nil {
		http.Error(rw, "unable to retrieve JWKs", http.StatusInternalServerError)
		return
	}

	var verifiedOIDCClaimSet OIDCClaimSet
	rawJWT, _, err := jwt.VerifyJWS(jwsObject, jwks)
	if err != nil {
		http.Error(rw, "unable to verify ID token using JWKs", http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal(rawJWT, &verifiedOIDCClaimSet); err != nil {
		http.Error(rw, "unable to unmarshal to ID token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(rw, string(rawJWT))

	// Verify aud
	if verifiedOIDCClaimSet.Aud != h.ClientID {
		http.Error(rw, "aud != client_id", http.StatusInternalServerError)
		return
	}

	// Verify iss
	if verifiedOIDCClaimSet.Iss != "https://accounts.google.com" {
		http.Error(rw, "iss != https://accounts.google.com", http.StatusInternalServerError)
		return
	}

	// Verify exp (expiration time)
	skew := time.Second
	if !jwt.VerifyExp(skew, verifiedOIDCClaimSet.Exp) {
		http.Error(rw, "token has been expired.", http.StatusInternalServerError)
		return
	}
}

func (h *OIDCHandler) HandleLogin(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "welcome!")
}

func main() {
	port := os.Getenv("PORT")
	host := os.Getenv("HOST")
	if port == "" {
		port = "8000"
	}

	oidcHandler := &OIDCHandler{
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		JWKSetURL:    os.Getenv("OIDC_JWKSET_URI"),
		JWKsFetcher:  &jwt.JWKsHTTPFetcher{},
	}

	r := mux.NewRouter()
	r.HandleFunc("/oidc/auth", oidcHandler.HandleAuth)
	r.HandleFunc("/oidc/auth/callback", oidcHandler.HandleCallback)
	r.HandleFunc("/oidc/auth/login", oidcHandler.HandleLogin)

	n := negroni.Classic()
	n.UseHandler(r)
	n.Run(host + ":" + port)
}
