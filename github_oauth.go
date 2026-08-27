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
	"html/template"
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

// githubDevice is an in-flight device-flow session keyed by our own poll
// token, capturing the originating authorize parameters so we can mint a code.
type githubDevice struct {
	ptk             string
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

var githubLoginPage = template.Must(template.New("gh").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in with GitHub · Signet</title>
<style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#10141c;color:#ecf2ff;display:grid;place-items:center;min-height:100vh;margin:0}.card{width:min(92vw,440px);padding:36px;border:1px solid #34445c;border-radius:16px;background:#161c28}.code{font-size:2rem;letter-spacing:.15em;color:#9dd6ff;font-weight:800}.uri{overflow-wrap:anywhere}.pending{color:#9db1cd}.err{color:#ff8fa3}</style></head><body>
<div class="card"><p class="intro">Go to <a class="uri" href="{{.URI}}">{{.URI}}</a> and enter the code:</p>
<p class="code">{{.UserCode}}</p>
<p class="pending" id="status">Waiting for authorization…</p></div>
<script>
const ptk="{{.PTK}}";
(async function poll(){
  try{
    const r=await fetch("/auth/github/status/"+ptk,{headers:{Accept:"application/json"}});
    const j=await r.json();
    if(j.status==="ready"){ window.location.assign(j.redirect_url); return; }
    if(j.status==="error"){ document.getElementById("status").textContent="Error: "+j.error; return; }
  }catch(e){}
  setTimeout(poll, {{.Interval}}*1000);
})();
</script></body></html>`))

// githubLogin starts a device flow and renders the user-facing code page.
func (s *Server) githubLogin(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.GitHubOAuthCfg()
	if !cfg.Enabled() {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	dev, err := startGithubDevice(cfg.ClientID)
	if err != nil {
		http.Error(w, "could not start GitHub device flow: "+err.Error(), http.StatusBadGateway)
		return
	}
	dev.ptk, _ = randomString(16)
	dev.clientID = query.Get("client_id")
	dev.redirectURI = query.Get("redirect_uri")
	dev.scope = query.Get("scope")
	dev.codeChallenge = query.Get("code_challenge")
	dev.nonce = query.Get("nonce")
	dev.stateParam = query.Get("state")

	s.mu <- struct{}{}
	for k, d := range s.ghDevs {
		if time.Now().After(d.expiresAt) {
			delete(s.ghDevs, k)
		}
	}
	s.ghDevs[dev.ptk] = dev
	<-s.mu

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = githubLoginPage.Execute(w, map[string]string{
		"URI": dev.verificationURI, "UserCode": dev.userCode,
		"PTK": dev.ptk, "Interval": fmt.Sprint(dev.interval),
	})
}

// githubStatus polls the device flow on behalf of a running browser session.
// It returns JSON so the page can auto-advance; on success it mints a signet
// authorization code and reports the redirect_url once.
func (s *Server) githubStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.GitHubOAuthCfg()
	if !cfg.Enabled() {
		http.Error(w, "GitHub federated login is not configured", http.StatusNotFound)
		return
	}
	ptk := trimPathPrefix(r.URL.Path, "/auth/github/status/")

	var dev *githubDevice
	s.mu <- struct{}{}
	dev = s.ghDevs[ptk]
	<-s.mu
	if dev == nil {
		s.json(w, map[string]string{"status": "error", "error": "expired_session"})
		return
	}
	if time.Now().After(dev.expiresAt) {
		s.json(w, map[string]string{"status": "error", "error": "expired"})
		return
	}
	if dev.done {
		s.json(w, map[string]string{"status": "ready", "redirect_url": dev.doneRedirect})
		return
	}

	accessToken, err := pollGithubToken(cfg.ClientID, dev.deviceCode)
	if err != nil {
		// authorization_pending is the expected transient error.
		s.json(w, map[string]string{"status": "pending"})
		return
	}

	profile, orgs, err := fetchGithubIdentity(accessToken)
	if err != nil {
		s.json(w, map[string]string{"status": "error", "error": "identity_fetch_failed"})
		return
	}
	if !cfg.allows(profile.Login, orgs) {
		s.json(w, map[string]string{"status": "error", "error": "not_allowed"})
		return
	}

	redirect := s.mintGithubCode(dev, profile)
	s.mu <- struct{}{}
	dev.done = true
	dev.doneRedirect = redirect
	<-s.mu
	s.json(w, map[string]string{"status": "ready", "redirect_url": redirect})
}

// mintGithubCode validates the stored authorize params were for a real client
// and issues an authorization code bound to the GitHub identity, then returns
// the full redirect URL (mirrors the password path in authorize).
func (s *Server) mintGithubCode(dev *githubDevice, profile *githubProfile) string {
	client, ok := s.store.Client(dev.clientID)
	if !ok || !allowedRedirect(client, dev.redirectURI) {
		return "/auth/github/status/" + dev.ptk + "?error=invalid_client"
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
	return redirect.String()
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
		return false // purely allow list -> nobody by default
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

func trimPathPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}
