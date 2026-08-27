package main

import (
	"bytes"
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
		var list []string
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

func testServerGitHub(t *testing.T, seed *Config) *Server {
	t.Helper()
	store, err := LoadOrCreateStore(t.TempDir(), "http://issuer.test", seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddClient(Client{ID: "client", Secret: "fixture-secret", RedirectURLs: []string{"http://client.test/callback"}}); err != nil {
		t.Fatal(err)
	}
	return NewServer(store)
}

func ghStart(t *testing.T, s *Server) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"client_id": "client", "redirect_uri": "http://client.test/callback",
		"code_challenge": pkceChallenge("verifier"), "code_challenge_method": "S256",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/github/device", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device start status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID       string `json:"id"`
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID == "" || resp.UserCode == "" {
		t.Fatalf("start missing id/user_code: %s", rec.Body.String())
	}
	return resp.ID, resp.UserCode
}

func ghStatus(t *testing.T, s *Server, id string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id": id})
	req := httptest.NewRequest(http.MethodPost, "/auth/github/device/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestGitHubDeviceFlowToCode(t *testing.T) {
	githubTestServer(t, "octocat", []string{"acme"}, false)
	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})

	id, _ := ghStart(t, s)
	status, resp := ghStatus(t, s, id)
	if status != http.StatusOK {
		t.Fatalf("status code = %d, body %s", status, resp)
	}
	if resp["status"] != "authenticated" {
		t.Fatalf("status = %v", resp["status"])
	}
	redirect, _ := resp["redirect_url"].(string)
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatal("missing code in redirect")
	}

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

	id, _ := ghStart(t, s)
	status, resp := ghStatus(t, s, id)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
	if resp["error"] != "access_denied" {
		t.Fatalf("expected access_denied, got %v", resp)
	}
}

func TestGitHubStatusPendingThenReady(t *testing.T) {
	githubTestServer(t, "octocat", []string{"acme"}, true) // first token poll -> pending
	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})

	id, _ := ghStart(t, s)
	status, _ := ghStatus(t, s, id)
	if status != http.StatusAccepted {
		t.Fatalf("expected 202 pending on first poll, got %d", status)
	}
	status, resp := ghStatus(t, s, id)
	if status != http.StatusOK {
		t.Fatalf("expected 200 on second poll, got %d", status)
	}
	if resp["status"] != "authenticated" {
		t.Fatalf("status = %v", resp["status"])
	}
}

func TestGitHubStatusPollParsesJSONTokenResponse(t *testing.T) {
	oldD, oldT, oldU, oldO := githubDeviceCodeURL, githubTokenURL, githubUserURL, githubOrgsURL
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_code":"dcx","user_code":"ABCD-1234","verification_uri":"https://example.com/device","expires_in":900,"interval":1}`))
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_json_token","token_type":"bearer","scope":"read:user"}`))
	})
	mux.HandleFunc("/api.github.com/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"login":"octocat","name":"Test User","email":"test@example.com"}`))
	})
	mux.HandleFunc("/api.github.com/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
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

	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})
	id, _ := ghStart(t, s)
	status, resp := ghStatus(t, s, id)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for JSON token response, got %d: %s", status, resp)
	}
	if resp["status"] != "authenticated" {
		t.Fatalf("status = %v", resp["status"])
	}
	redirect, _ := resp["redirect_url"].(string)
	if u, err := url.Parse(redirect); err != nil || u.Query().Get("code") == "" {
		t.Fatalf("missing code in redirect: %s", redirect)
	}
}

func TestGitHubDeviceCancel(t *testing.T) {
	githubTestServer(t, "octocat", nil, false)
	s := testServerGitHub(t, &Config{GitHub: &GitHubOAuth{ClientID: "test-app", AllowedLogins: []string{"octocat"}}})

	id, _ := ghStart(t, s)
	body, _ := json.Marshal(map[string]string{"id": id})
	req := httptest.NewRequest(http.MethodPost, "/auth/github/device/cancel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cancel status = %d", rec.Code)
	}
	// session should be gone
	status, _ := ghStatus(t, s, id)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 after cancel, got %d", status)
	}
}
