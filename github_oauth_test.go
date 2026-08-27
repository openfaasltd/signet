package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func githubTestServer(t *testing.T, login string, orgs []string, pendingFirst bool) *httptest.Server {
	oldD, oldT, oldU, oldO := githubDeviceCodeURL, githubTokenURL, githubUserURL, githubOrgsURL
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "test-app" {
			t.Errorf("device/code client_id = %q", r.Form.Get("client_id"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_code":"dc-1","user_code":"ABCD-EFGH","verification_uri":"https://example.com/device","expires_in":900,"interval":1}`))
	})
	pending := pendingFirst
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		if pending {
			pending = false
			_, _ = w.Write([]byte("error=authorization_pending&error_description=not+yet"))
			return
		}
		_, _ = w.Write([]byte("access_token=gho_token&token_type=bearer&scope=read%3Auser"))
	})
	mux.HandleFunc("/api.github.com/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_token" {
			t.Errorf("user auth = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"login":"` + login + `","name":"Test User","email":"test@example.com"}`))
	})
	mux.HandleFunc("/api.github.com/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		list := []string{}
		for _, o := range orgs {
			list = append(list, `{"login":"`+o+`"}`)
		}
		_, _ = w.Write([]byte("[" + strings.Join(list, ",") + "]"))
	})
	ts := httptest.NewServer(mux)
	githubDeviceCodeURL = ts.URL + "/login/device/code"
	githubTokenURL = ts.URL + "/login/oauth/access_token"
	githubUserURL = ts.URL + "/api.github.com/user"
	githubOrgsURL = ts.URL + "/api.github.com/user/orgs"
	t.Cleanup(func() {
		ts.Close()
		githubDeviceCodeURL, githubTokenURL, githubUserURL, githubOrgsURL = oldD, oldT, oldU, oldO
	})
	return ts
}

func TestGitHubDeviceFlowToCode(t *testing.T) {
	githubTestServer(t, "octocat", []string{"acme"}, false)
	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})

	query := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://client.test/callback"}, "code_challenge": {pkceChallenge("verifier")}, "code_challenge_method": {"S256"}}
	req := httptest.NewRequest(http.MethodGet, "/auth/github?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login page status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ABCD-EFGH") {
		t.Fatal("login page should show the user code")
	}

	// Poll status -> token available -> code minted.
	ptk := extractPTK(t, body)
	statusReq := httptest.NewRequest(http.MethodGet, "/auth/github/status/"+ptk, nil)
	statusReq.Header.Set("Accept", "application/json")
	statusRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(statusRec, statusReq)
	var resp struct {
		Status      string `json:"status"`
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ready" {
		t.Fatalf("expected ready, got %s: %s", resp.Status, statusRec.Body.String())
	}
	u, err := url.Parse(resp.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatal("missing code in redirect")
	}

	// Exchange the code -> token issued with GitHub identity claims.
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://client.test/callback"}, "code_verifier": {"verifier"}}
	treq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	treq.SetBasicAuth("client", "fixture-secret")
	trec := httptest.NewRecorder()
	s.Handler().ServeHTTP(trec, treq)
	if trec.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", trec.Code, trec.Body.String())
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(trec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	claims, err := verifyJWT(tokens.IDToken, &s.store.Key().PublicKey)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims["sub"] != "octocat" {
		t.Fatalf("sub = %v, want octocat", claims["sub"])
	}
	if claims["email"] != "test@example.com" {
		t.Fatalf("email = %v, want test@example.com", claims["email"])
	}
}

func TestGitHubAllowlistRejects(t *testing.T) {
	githubTestServer(t, "someone-else", nil, false)
	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})

	req := httptest.NewRequest(http.MethodGet, "/auth/github?"+url.Values{"client_id": {"client"}, "redirect_uri": {"http://client.test/callback"}}.Encode(), nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	ptk := extractPTK(t, rec.Body.String())
	status := httptest.NewRecorder()
	s.Handler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/auth/github/status/"+ptk, nil))
	var resp map[string]string
	_ = json.Unmarshal(status.Body.Bytes(), &resp)
	if resp["status"] != "error" || resp["error"] != "not_allowed" {
		t.Fatalf("expected not_allowed, got %s", status.Body.String())
	}
}

func TestGitHubStatusPendingThenReady(t *testing.T) {
	githubTestServer(t, "octocat", []string{"acme"}, true) // first token poll -> pending
	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})

	req := httptest.NewRequest(http.MethodGet, "/auth/github?"+url.Values{"client_id": {"client"}, "redirect_uri": {"http://client.test/callback"}}.Encode(), nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	ptk := extractPTK(t, rec.Body.String())

	status := httptest.NewRecorder()
	s.Handler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/auth/github/status/"+ptk, nil))
	var first map[string]string
	_ = json.Unmarshal(status.Body.Bytes(), &first)
	if first["status"] != "pending" {
		t.Fatalf("expected pending, got %s", status.Body.String())
	}

	status2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(status2, httptest.NewRequest(http.MethodGet, "/auth/github/status/"+ptk, nil))
	var second map[string]string
	_ = json.Unmarshal(status2.Body.Bytes(), &second)
	if second["status"] != "ready" {
		t.Fatalf("expected ready on second poll, got %s", status2.Body.String())
	}
}

func extractPTK(t *testing.T, body string) string {
	t.Helper()
	const k = `const ptk="`
	i := strings.Index(body, k)
	if i < 0 {
		t.Fatalf("ptk not found in page")
	}
	rest := body[i+len(k):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}

func testServerGitHub(t *testing.T, seed *Config) *Server {
	t.Helper()
	store, err := LoadOrCreateStore(t.TempDir(), "http://issuer.test", seed)
	if err != nil {
		t.Fatal(err)
	}
	// Confidential fixture so the code can be minted and later exchanged via
	// BasicAuth (deterministic secret for the test).
	_, _, err = store.AddClient(Client{ID: "client", Secret: "fixture-secret", RedirectURLs: []string{"http://client.test/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(store)
}
