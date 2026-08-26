package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	store, err := LoadOrCreateStore(t.TempDir(), "http://issuer.test", &Config{
		Users:   []User{{Username: "admin", Password: "secret", Subject: "user-1", Name: "Admin"}},
		Clients: []Client{{ID: "client", Secret: "secret", RedirectURLs: []string{"http://client.test/callback"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(store)
}

func TestDiscovery(t *testing.T) {
	r := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if r.Code != http.StatusOK {
		t.Fatalf("status = %d", r.Code)
	}
	var discovery map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["issuer"] != "http://issuer.test" {
		t.Fatalf("issuer = %v", discovery["issuer"])
	}
	if discovery["jwks_uri"] != "http://issuer.test/.well-known/jwks.json" {
		t.Fatalf("jwks_uri = %v", discovery["jwks_uri"])
	}
}

func TestHome(t *testing.T) {
	r := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/", nil))
	if r.Code != http.StatusOK {
		t.Fatalf("status = %d", r.Code)
	}
	if !strings.Contains(r.Body.String(), "OpenID Connect metadata") {
		t.Fatalf("landing page did not contain metadata link")
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	s := testServer(t)
	query := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://client.test/callback"}, "scope": {"openid profile"}, "state": {"state-1"}, "code_challenge": {pkceChallenge("verifier")}, "code_challenge_method": {"S256"}}
	login := httptest.NewRecorder()
	s.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d", login.Code)
	}

	form := url.Values{"username": {"admin"}, "password": {"secret"}}
	request := httptest.NewRequest(http.MethodPost, "/authorize?"+query.Encode(), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authorise := httptest.NewRecorder()
	s.Handler().ServeHTTP(authorise, request)
	if authorise.Code != http.StatusFound {
		t.Fatalf("authorise status = %d", authorise.Code)
	}
	location, err := authorise.Result().Location()
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("missing code")
	}

	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://client.test/callback"}, "code_verifier": {"verifier"}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.SetBasicAuth("client", "secret")
	tokens := httptest.NewRecorder()
	s.Handler().ServeHTTP(tokens, tokenRequest)
	if tokens.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", tokens.Code, tokens.Body.String())
	}
	var response struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tokens.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(response.IDToken, &s.store.Key().PublicKey); err != nil {
		t.Fatal(err)
	}
}
