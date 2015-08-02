package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/nabeken/jwt.go"
	"github.com/square/go-jose"
)

var tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"

type OIDCHandler struct {
	ClientID     string
	ClientSecret string

	JWKFetcher *jwt.JWKFetcher
}

func (h *OIDCHandler) HandleAuth(rw http.ResponseWriter, req *http.Request) {
	v := url.Values{}
	v.Set("client_id", h.ClientID)
	v.Set("response_type", "code")
	v.Set("scope", "openid email")
	v.Set("redirect_uri", "http://oidc.dev:8000/oidc/auth/callback")
	v.Set("state", jwt.StateToken())
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

	tokenResp := jwt.OAuth2TokenResponse{}
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
	jwks, err := h.JWKFetcher.FetchJWK()
	if err != nil {
		http.Error(rw, "unable to retrieve JWKs", http.StatusInternalServerError)
		return
	}

	var verified bool
	var verifiedOIDCClaimSet jwt.OIDCClaimSet
	for _, jwk := range jwks {
		fmt.Fprintln(rw, "Using JWK", jwk.KeyID)
		rawIdToken, err := jwsObject.Verify(jwk)
		if err != nil {
			fmt.Fprintln(rw, "unable to verify ID token:", err)
			continue
		}

		err = json.Unmarshal(rawIdToken, &verifiedOIDCClaimSet)
		if err != nil {
			fmt.Fprintln(rw, "unable to parse ID Token:", err)
			continue
		}
		fmt.Fprintln(rw, "successed to verify and parse ID Token with KID", jwk.KeyID)
		verified = true
		break
	}
	if !verified {
		http.Error(rw, "unable to verify ID token using JWKs", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(rw, verifiedOIDCClaimSet)
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
		JWKFetcher: &jwt.JWKFetcher{
			URI: os.Getenv("OIDC_JWKSET_URI"),
		},
	}

	r := mux.NewRouter()
	r.HandleFunc("/oidc/auth", oidcHandler.HandleAuth)
	r.HandleFunc("/oidc/auth/callback", oidcHandler.HandleCallback)
	r.HandleFunc("/oidc/auth/login", oidcHandler.HandleLogin)

	n := negroni.Classic()
	n.UseHandler(r)
	n.Run(host + ":" + port)
}
