package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"time"
)

//go:embed web/*
var webFS embed.FS

// pageTemplates are the HTML pages served from the embedded web assets.
var pageTemplates = template.Must(template.ParseFS(webFS, "web/home.html", "web/login.html"))

// noCache disables content caching so a newly shipped binary is always
// reflected on the next reload (no stale etags/browser cache).
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// cspPage applies a strict Content Security Policy (no inline scripts or
// styles) plus no-cache to a page response.
func cspPage(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

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
	mux.HandleFunc("/auth/github/device", s.githubDeviceStart)
	mux.HandleFunc("/auth/github/device/status", s.githubDeviceStatus)
	mux.HandleFunc("/auth/github/device/cancel", s.githubDeviceCancel)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/admin/", s.adminHandler())
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", noCache(http.FileServer(http.FS(webRoot)))))
	return mux
}

type homeData struct {
	Issuer string
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cspPage(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplates.ExecuteTemplate(w, "home.html", homeData{Issuer: s.store.Issuer})
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
		params, _ := json.Marshal(map[string]string{
			"client_id":             client.ID,
			"redirect_uri":          query.Get("redirect_uri"),
			"scope":                 query.Get("scope"),
			"code_challenge":        query.Get("code_challenge"),
			"nonce":                 query.Get("nonce"),
			"state":                 query.Get("state"),
			"code_challenge_method": query.Get("code_challenge_method"),
		})
		data.GitHubEnabled = true
		data.GitHubParamsB64 = base64.StdEncoding.EncodeToString(params)
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

type loginData struct {
	Action, ClientID, Scope, Username, Error string
	GitHubEnabled                            bool
	GitHubParamsB64                          string
}

func (s *Server) login(w http.ResponseWriter, data loginData) {
	cspPage(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplates.ExecuteTemplate(w, "login.html", data)
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
