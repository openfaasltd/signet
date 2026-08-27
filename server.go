package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Server struct {
	store  *Store
	codes  map[string]authCode
	mu     chan struct{} // serialises code-map and device-map access
	ghDevs map[string]*githubDevice
}

type authCode struct {
	ClientID, RedirectURI, Subject, Nonce, CodeChallenge, Name, Email string
	Groups                                                            []string
	Expires                                                           time.Time
}

func NewServer(store *Store) *Server {
	return &Server{store: store, codes: map[string]authCode{}, mu: make(chan struct{}, 1), ghDevs: map[string]*githubDevice{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/.well-known/jwks.json", s.jwks)
	mux.HandleFunc("/jwks.json", s.jwks)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/auth/github", s.githubLogin)
	mux.HandleFunc("/auth/github/status/", s.githubStatus)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/admin/", s.adminHandler())
	return mux
}

type homeData struct {
	Issuer string
}

var homeTemplate = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signet by OpenFaaS Ltd</title>
<style>
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #10141c; color: #ecf2ff; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: radial-gradient(circle at top left, #273c58, transparent 42%), #10141c; }
main { width: min(680px, calc(100% - 48px)); padding: 52px; border: 1px solid #34445c; border-radius: 20px; background: rgba(16, 20, 28, .8); box-shadow: 0 24px 80px #0007; }
.brand { display: flex; align-items: center; gap: 16px; }
.mark { width: 42px; height: 42px; display: grid; place-items: center; border-radius: 12px; background: #9dd6ff; color: #102033; font-size: 23px; font-weight: 800; }
h1 { margin: 0; font-size: clamp(2.2rem, 6vw, 3.6rem); letter-spacing: -.06em; }
.byline { margin-left: .35em; color: #9db1cd; font-size: .38em; font-weight: 600; letter-spacing: -.02em; white-space: nowrap; }
p { color: #b8c7dc; line-height: 1.6; }
.issuer { margin: 28px 0; padding: 15px 17px; border-radius: 10px; background: #172233; color: #dbeaff; font-family: ui-monospace, SFMono-Regular, monospace; overflow-wrap: anywhere; }
nav { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 30px; }
a { color: #102033; background: #9dd6ff; padding: 11px 15px; border-radius: 9px; text-decoration: none; font-weight: 700; }
a.secondary { color: #c5d8f2; background: transparent; border: 1px solid #4a607d; }
footer { margin-top: 38px; font-size: .88rem; color: #8294ac; }
</style>
</head>
<body>
<main>
  <div class="brand"><div class="mark">S</div><h1>Signet<span class="byline">by OpenFaaS Ltd</span></h1></div>
  <p>A lightweight OpenID Connect provider for agents and automation.</p>
  <div class="issuer">{{.Issuer}}</div>
  <nav>
    <a href="/.well-known/openid-configuration">OpenID Connect metadata</a>
    <a class="secondary" href="/.well-known/jwks.json">JWKS</a>
    <a class="secondary" href="/healthz">Health</a>
  </nav>
  <footer>OpenID Connect · ES256 signing · PKCE (S256)</footer>
</main>
</body>
</html>`))

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTemplate.Execute(w, homeData{Issuer: s.store.Issuer})
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	s.json(w, map[string]any{
		"issuer": s.store.Issuer, "authorization_endpoint": s.store.Issuer + "/authorize",
		"token_endpoint": s.store.Issuer + "/token", "jwks_uri": s.store.Issuer + "/.well-known/jwks.json",
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "email", "groups"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"}, "code_challenge_methods_supported": []string{"S256"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	key := s.store.Key()
	s.json(w, map[string]any{"keys": []map[string]any{{"kty": "EC", "use": "sig", "kid": "signet-1", "alg": "ES256", "crv": "P-256", "x": jwkCoordinate(key.PublicKey.X), "y": jwkCoordinate(key.PublicKey.Y)}}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("response_type") != "code" || query.Get("client_id") == "" || query.Get("redirect_uri") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	client, ok := s.store.Client(query.Get("client_id"))
	if !ok || !allowedRedirect(client, query.Get("redirect_uri")) {
		http.Error(w, "invalid client or redirect URI", http.StatusBadRequest)
		return
	}
	// Public clients (no secret) must use PKCE S256.
	if client.Secret == "" && (query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256") {
		http.Error(w, "PKCE S256 is required for public clients", http.StatusBadRequest)
		return
	}
	data := loginData{Action: r.URL.RequestURI(), ClientID: client.ID, Scope: query.Get("scope"), Username: query.Get("login_hint")}
	if gh := s.store.GitHubOAuthCfg(); gh.Enabled() {
		data.GitHubLink = "/auth/github?" + query.Encode()
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid login", http.StatusBadRequest)
			return
		}
		user, found := s.store.User(r.Form.Get("username"))
		if !found || user.Password != r.Form.Get("password") {
			data.Error = "Invalid username or password"
			s.login(w, data)
			return
		}
		code, err := randomString(32)
		if err != nil {
			http.Error(w, "could not create authorization code", http.StatusInternalServerError)
			return
		}
		s.mu <- struct{}{}
		for value, pending := range s.codes {
			if time.Now().After(pending.Expires) {
				delete(s.codes, value)
			}
		}
		s.codes[code] = authCode{ClientID: client.ID, RedirectURI: query.Get("redirect_uri"), Subject: user.Subject, Nonce: query.Get("nonce"), CodeChallenge: query.Get("code_challenge"), Expires: time.Now().Add(2 * time.Minute)}
		<-s.mu
		redirect, _ := url.Parse(query.Get("redirect_uri"))
		params := redirect.Query()
		params.Set("code", code)
		if state := query.Get("state"); state != "" {
			params.Set("state", state)
		}
		redirect.RawQuery = params.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
		return
	}
	s.login(w, data)
}

type loginData struct{ Action, ClientID, Scope, Username, Error, GitHubLink string }

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · Signet by OpenFaaS Ltd</title>
<style>
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
* { box-sizing: border-box; }
body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px; background: radial-gradient(circle at top left, #273c58, transparent 42%), #10141c; color: #ecf2ff; }
main { width: min(100%, 440px); padding: 40px; border: 1px solid #34445c; border-radius: 16px; background: rgba(16, 20, 28, .88); box-shadow: 0 28px 76px #0006; }
.brand { display: flex; align-items: center; gap: 10px; margin-bottom: 28px; }
.mark { width: 30px; height: 30px; display: grid; place-items: center; border-radius: 8px; background: #9dd6ff; color: #102033; font-size: 16px; font-weight: 800; }
.wordmark { font-size: 1rem; font-weight: 800; letter-spacing: -.04em; }
.byline { margin-left: .45em; color: #9db1cd; font-size: .68rem; font-weight: 600; letter-spacing: -.01em; }
h1 { margin: 0; font-size: clamp(1.8rem, 7vw, 2.25rem); letter-spacing: -.05em; }
.intro { margin: 8px 0 26px; color: #b8c7dc; line-height: 1.5; }
.client { color: #ecf2ff; font-weight: 700; }
form { display: grid; gap: 14px; }
label { display: grid; gap: 8px; color: #c5d8f2; font-size: .92rem; font-weight: 650; }
input { width: 100%; min-height: 42px; padding: 9px 12px; border: 1px solid #4a607d; border-radius: 8px; outline: none; background: #172233; color: #ecf2ff; font: inherit; }
input:focus { border-color: #9dd6ff; box-shadow: 0 0 0 3px #9dd6ff2b; }
button { min-height: 42px; margin-top: 4px; border: 0; border-radius: 8px; background: #9dd6ff; color: #102033; cursor: pointer; font: inherit; font-weight: 800; }
button:hover { background: #b8e3ff; }
.error { margin: 0 0 20px; padding: 12px 14px; border: 1px solid #b95768; border-radius: 9px; background: #512934; color: #ffd8de; line-height: 1.45; }
</style>
</head>
<body>
<main>
  <div class="brand"><div class="mark">S</div><div class="wordmark">Signet<span class="byline">by OpenFaaS Ltd</span></div></div>
  <h1>Sign in</h1>
  <p class="intro">Sign in to <span class="client">{{.ClientID}}</span>.</p>
  {{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
  <form method="post" action="{{.Action}}">
    <label>Username<input name="username" value="{{.Username}}" autocomplete="username" autofocus></label>
    <label>Password<input type="password" name="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
  {{if .GitHubLink}}<p style="text-align:center;margin:18px 0 0;"><a style="display:block;padding:12px 16px;border-radius:9px;background:#24292f;color:#ffffff;font-weight:700;text-decoration:none;" href="{{.GitHubLink}}">Sign in with GitHub</a></p>{{end}}
</main>
</body>
</html>`))

func (s *Server) login(w http.ResponseWriter, data loginData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginTemplate.Execute(w, data)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.oauthError(w, "invalid_request", "invalid request")
		return
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	client, found := s.store.Client(clientID)
	if !found {
		s.oauthError(w, "invalid_client", "invalid client authentication")
		return
	}
	grantType := r.Form.Get("grant_type")

	if grantType == "client_credentials" {
		if client.Secret == "" || subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) != 1 {
			s.oauthError(w, "invalid_client", "invalid client authentication")
			return
		}
		subject := client.Subject
		if subject == "" {
			subject = client.ID
		}
		now := time.Now()
		claims := map[string]any{"iss": s.store.Issuer, "sub": subject, "aud": []string{client.ID}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "groups": client.Groups}
		s.issueToken(w, claims, r.Form.Get("scope"))
		return
	}

	if grantType != "authorization_code" {
		s.oauthError(w, "unsupported_grant_type", "grant type is not supported")
		return
	}
	// Confidential clients must authenticate with their secret on the code
	// grant; public clients prove possession via PKCE only.
	if client.Secret != "" && subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) != 1 {
		s.oauthError(w, "invalid_client", "invalid client authentication")
		return
	}
	code := r.Form.Get("code")
	s.mu <- struct{}{}
	entry, exists := s.codes[code]
	delete(s.codes, code)
	<-s.mu
	if !exists || time.Now().After(entry.Expires) || entry.ClientID != client.ID || entry.RedirectURI != r.Form.Get("redirect_uri") {
		s.oauthError(w, "invalid_grant", "invalid authorization code")
		return
	}
	if challenge := entry.CodeChallenge; challenge != "" && challenge != pkceChallenge(r.Form.Get("code_verifier")) {
		s.oauthError(w, "invalid_grant", "PKCE verification failed")
		return
	}
	user, found := s.store.UserBySubject(entry.Subject)
	name, email, groups := entry.Name, entry.Email, entry.Groups
	if found && (user.Name != "" || user.Email != "" || len(user.Groups) > 0) {
		name, email, groups = user.Name, user.Email, user.Groups
	}
	now := time.Now()
	claims := map[string]any{"iss": s.store.Issuer, "sub": entry.Subject, "aud": []string{client.ID}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "auth_time": now.Unix(), "name": name, "email": email, "groups": groups}
	if entry.Nonce != "" {
		claims["nonce"] = entry.Nonce
	}
	s.issueToken(w, claims, r.Form.Get("scope"))
}

func (s *Server) issueToken(w http.ResponseWriter, claims map[string]any, scope string) {
	idToken, err := signJWT(s.store.Key(), claims)
	if err != nil {
		s.oauthError(w, "server_error", err.Error())
		return
	}
	s.json(w, map[string]any{"access_token": idToken, "id_token": idToken, "token_type": "Bearer", "expires_in": 3600, "scope": scope})
}

func allowedRedirect(client Client, redirect string) bool {
	for _, allowed := range client.RedirectURLs {
		if allowed == redirect {
			return true
		}
	}
	return false
}

func (s *Server) json(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) oauthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	s.json(w, map[string]string{"error": code, "error_description": description})
}

func randomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return rawURL.EncodeToString(sum[:])
}
