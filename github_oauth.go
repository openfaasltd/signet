package main

// Federated login via GitHub OAuth Device Flow, mirroring superterm/slicer:
// a client_id only (no client_secret, no redirect to register). GitHub is
// trusted as the source of truth for WHO the user is; authorization is then a
// pure allowlist (default deny). Signet still issues its own authorization
// code and tokens downstream.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHub endpoints are package vars so tests can substitute a mock server.
var (
	githubDeviceCodeURL = "https://github.com/login/device/code"
	githubTokenURL      = "https://github.com/login/oauth/access_token"
	githubUserURL       = "https://api.github.com/user"
	githubOrgsURL       = "https://api.github.com/user/orgs"
)

const githubDeviceTTL = 10 * time.Minute

// DeviceAuth is the body GitHub returns from POST /login/device/code.
type DeviceAuth struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// githubDevice is an in-flight device-flow session keyed by our own poll id,
// capturing the originating authorize parameters so we can mint a code.
type githubDevice struct {
	id              string
	deviceCode      string
	userCode        string
	verificationURI string
	interval        int
	expiresAt       time.Time

	clientID      string
	redirectURI   string
	scope         string
	codeChallenge string
	nonce         string
	stateParam    string

	doneRedirect string
	done         bool
}

// githubDeviceStart begins a device flow and returns the session plus the
// short-lived code the operator must enter at GitHub. Mirrors superterm's
// handleGitHubDeviceStart.
func (s *Server) githubDeviceStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.store.GitHubOAuthCfg()
	if !cfg.Enabled() {
		http.Error(w, "github auth is not configured", http.StatusNotFound)
		return
	}
	var p struct {
		ClientID      string `json:"client_id"`
		RedirectURI   string `json:"redirect_uri"`
		Scope         string `json:"scope"`
		CodeChallenge string `json:"code_challenge"`
		Nonce         string `json:"nonce"`
		State         string `json:"state"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)

	dev, err := startGithubDevice(cfg.ClientID)
	if err != nil {
		http.Error(w, "github login failed", http.StatusBadGateway)
		return
	}
	dev.id, _ = randomString(16)
	dev.clientID = p.ClientID
	dev.redirectURI = p.RedirectURI
	dev.scope = p.Scope
	dev.codeChallenge = p.CodeChallenge
	dev.nonce = p.Nonce
	dev.stateParam = p.State

	s.mu <- struct{}{}
	for k, d := range s.ghDevs {
		if time.Now().After(d.expiresAt) {
			delete(s.ghDevs, k)
		}
	}
	s.ghDevs[dev.id] = dev
	<-s.mu

	expires := int(time.Until(dev.expiresAt).Seconds())
	if expires <= 0 {
		expires = dev.interval * 2
	}
	s.json(w, map[string]any{
		"id": dev.id, "user_code": dev.userCode,
		"verification_uri": dev.verificationURI,
		"expires_in":       expires, "interval": dev.interval,
	})
}

// githubDeviceStatus polls the device flow. Mirrors superterm's status
// protocol: 200 = authenticated (a signet code was minted), 202 = still
// pending (retry_after), 410 = expired, 403/401 = identity not allowed.
func (s *Server) githubDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.store.GitHubOAuthCfg()
	if !cfg.Enabled() {
		http.Error(w, "github auth is not configured", http.StatusNotFound)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var dev *githubDevice
	s.mu <- struct{}{}
	dev = s.ghDevs[body.ID]
	<-s.mu
	if dev == nil {
		http.Error(w, "unknown github login", http.StatusNotFound)
		return
	}
	if time.Now().After(dev.expiresAt) {
		s.mu <- struct{}{}
		delete(s.ghDevs, body.ID)
		<-s.mu
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired"})
		return
	}
	if dev.done {
		s.json(w, map[string]any{"status": "authenticated", "redirect_url": dev.doneRedirect})
		return
	}

	accessToken, err := pollGithubToken(cfg.ClientID, dev.deviceCode)
	if err != nil {
		if err == errPending {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "retry_after": dev.interval})
			return
		}
		http.Error(w, "github login failed", http.StatusBadGateway)
		return
	}

	profile, orgs, err := fetchGithubIdentity(accessToken)
	if err != nil {
		http.Error(w, "github profile failed", http.StatusBadGateway)
		return
	}
	if !cfg.allows(profile.Login, orgs) {
		s.mu <- struct{}{}
		delete(s.ghDevs, body.ID)
		<-s.mu
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
		return
	}

	redirect, ok := s.mintGithubCode(dev, profile)
	if !ok {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}
	s.mu <- struct{}{}
	dev.done = true
	dev.doneRedirect = redirect
	<-s.mu
	s.json(w, map[string]any{"status": "authenticated", "redirect_url": redirect})
}

// githubDeviceCancel abandons an in-flight device flow.
func (s *Server) githubDeviceCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.ID != "" {
		s.mu <- struct{}{}
		delete(s.ghDevs, body.ID)
		<-s.mu
	}
	w.WriteHeader(http.StatusNoContent)
}

// mintGithubCode validates the stored authorize params were for a real client
// and issues an authorization code bound to the GitHub identity, returning the
// full redirect URL and whether it succeeded.
func (s *Server) mintGithubCode(dev *githubDevice, profile *githubProfile) (string, bool) {
	client, ok := s.store.Client(dev.clientID)
	if !ok || !allowedRedirect(client, dev.redirectURI) {
		return "", false
	}

	code, _ := randomString(32)
	s.mu <- struct{}{}
	s.codes[code] = authCode{
		ClientID:      client.ID,
		RedirectURI:   dev.redirectURI,
		Subject:       profile.Login,
		Nonce:         dev.nonce,
		CodeChallenge: dev.codeChallenge,
		Name:          profile.Name,
		Email:         profile.Email,
		Expires:       time.Now().Add(2 * time.Minute),
	}
	<-s.mu

	redirect, _ := url.Parse(dev.redirectURI)
	params := redirect.Query()
	params.Set("code", code)
	if dev.stateParam != "" {
		params.Set("state", dev.stateParam)
	}
	redirect.RawQuery = params.Encode()
	return redirect.String(), true
}

// startGithubDevice requests a device code from GitHub for the given client.
func startGithubDevice(clientID string) (*githubDevice, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "read:user,user:email")
	req, err := http.NewRequest(http.MethodPost, githubDeviceCodeURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device/code HTTP %d", res.StatusCode)
	}
	var auth DeviceAuth
	if err := json.Unmarshal(body, &auth); err != nil {
		return nil, err
	}
	interval := auth.Interval
	if interval <= 0 {
		interval = 5
	}
	return &githubDevice{
		deviceCode:      auth.DeviceCode,
		userCode:        auth.UserCode,
		verificationURI: auth.VerificationURI,
		interval:        interval,
		expiresAt:       time.Now().Add(githubDeviceTTL),
	}, nil
}

// pollGithubToken exchanges the device code for an access token, returning an
// error while GitHub reports authorization_pending (the caller treats this as
// transient).
func pollGithubToken(clientID, deviceCode string) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("device_code", deviceCode)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	req, err := http.NewRequest(http.MethodPost, githubTokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	// GitHub honours Accept: application/json and returns JSON, but to be
	// robust we accept either the form-encoded response or a JSON object.
	var vals url.Values
	if strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		var j struct {
			AccessToken      string `json:"access_token"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &j); err != nil {
			return "", err
		}
		vals = url.Values{"error": {j.Error}, "error_description": {j.ErrorDescription}, "access_token": {j.AccessToken}}
	} else {
		p, err := url.ParseQuery(string(body))
		if err != nil {
			return "", err
		}
		vals = p
	}
	if vals.Get("error") == "authorization_pending" {
		return "", errPending
	}
	if tok := vals.Get("access_token"); tok != "" {
		return tok, nil
	}
	return "", fmt.Errorf("token exchange failed: %s", vals.Get("error_description"))
}

var errPending = fmt.Errorf("authorization_pending")

type githubProfile struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type githubOrg struct {
	Login string `json:"login"`
}

func fetchGithubIdentity(accessToken string) (*githubProfile, []string, error) {
	profile, err := getGithubJSON(githubUserURL, accessToken)
	if err != nil {
		return nil, nil, err
	}
	var p struct {
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(profile, &p); err != nil {
		return nil, nil, err
	}
	orgs := []string{}
	if body, err := getGithubJSON(githubOrgsURL, accessToken); err == nil {
		var list []githubOrg
		if json.Unmarshal(body, &list) == nil {
			for _, o := range list {
				orgs = append(orgs, o.Login)
			}
		}
	}
	return &githubProfile{Login: p.Login, Name: p.Name, Email: p.Email}, orgs, nil
}

func getGithubJSON(rawurl, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawurl, res.StatusCode)
	}
	return body, nil
}

// allows implements the pure allowlist. Default deny: at least one of
// AllowedLogins / AllowedOrgs must be configured and matched.
func (g *GitHubOAuth) allows(login string, orgs []string) bool {
	matchLogin := len(g.AllowedLogins) == 0 || containsString(g.AllowedLogins, login)
	matchOrg := len(g.AllowedOrgs) == 0 || intersectsString(g.AllowedOrgs, orgs)
	if len(g.AllowedLogins) == 0 && len(g.AllowedOrgs) == 0 {
		return false
	}
	return matchLogin && matchOrg
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func intersectsString(a, b []string) bool {
	for _, x := range a {
		if containsString(b, x) {
			return true
		}
	}
	return false
}
