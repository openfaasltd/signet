package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// clientFlags holds the connection flags shared by all client subcommands.
type clientFlags struct {
	url       string
	token     string
	tokenFile string
}

func (c *clientFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.url, "url", envOr("SIGNET_URL", "http://127.0.0.1:8080"), "Daemon URL (TCP: http://127.0.0.1:8080, or Unix socket: /path/to/signet.sock)")
	fs.StringVar(&c.token, "token", os.Getenv("SIGNET_ADMIN_TOKEN"), "Admin Bearer token")
	fs.StringVar(&c.tokenFile, "token-file", "", "Path to a file containing the admin token")
}

func (c *clientFlags) resolveToken() (string, error) {
	if c.token != "" {
		return c.token, nil
	}
	if c.tokenFile != "" {
		data, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

// httpClient builds an http.Client that dials a Unix socket when the target
// URL is a socket path, otherwise uses the default transport.
func httpClient(target string) *http.Client {
	if isSocketPath(target) {
		sock := strings.TrimPrefix(target, "unix://")
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
			},
			Timeout: 30 * time.Second,
		}
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// requestURL rewrites a Unix-socket target into a parseable http URL so the
// request path/query are preserved.
func requestURL(target, path string) string {
	if isSocketPath(target) {
		return "http://unix" + path
	}
	return target + path
}

func isSocketPath(target string) bool {
	if strings.HasPrefix(target, "unix://") {
		return true
	}
	// A bare path (no scheme) that exists or points at a socket.
	if !strings.Contains(target, "://") {
		if info, err := os.Stat(target); err == nil && info.Mode()&os.ModeSocket != 0 {
			return true
		}
	}
	return false
}

// doRequest performs an HTTP request against the daemon and returns the
// response body and status code.
func (c *clientFlags) doRequest(method, path string, body any) ([]byte, int, error) {
	token, err := c.resolveToken()
	if err != nil {
		return nil, 0, err
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, requestURL(c.url, path), reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := httpClient(c.url).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return data, res.StatusCode, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- user subcommands ---

func runUser(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: signet user <add|list|rm> ...")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add":
		return userAdd(rest)
	case "list":
		return userList(rest)
	case "rm", "remove", "delete":
		return userRemove(rest)
	default:
		return fmt.Errorf("unknown user subcommand %q", sub)
	}
}

func userAdd(args []string) error {
	cf := &clientFlags{}
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	cf.register(fs)
	groups := fs.String("groups", "", "Comma-separated groups")
	password := fs.String("password", "", "Password (generated if empty)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: signet user add <username> [--groups a,b] [--password X]")
	}
	username := fs.Arg(0)
	var g []string
	if *groups != "" {
		for _, part := range strings.Split(*groups, ",") {
			if part = strings.TrimSpace(part); part != "" {
				g = append(g, part)
			}
		}
	}
	data, status, err := cf.doRequest(http.MethodPost, "/admin/users", userRequest{Username: username, Password: *password, Groups: g})
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return adminResponseError(status, data)
	}
	var out struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.Unmarshal(data, &out)
	fmt.Printf("Created user %s\n", out.Username)
	fmt.Printf("Password: %s\n", out.Password)
	fmt.Println("Store this password now; it is only shown once.")
	return nil
}

func userList(args []string) error {
	cf := &clientFlags{}
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	cf.register(fs)
	fs.Parse(args)
	data, status, err := cf.doRequest(http.MethodGet, "/admin/users", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return adminResponseError(status, data)
	}
	var out struct {
		Users []User `json:"users"`
	}
	_ = json.Unmarshal(data, &out)
	if len(out.Users) == 0 {
		fmt.Println("No users.")
		return nil
	}
	for _, u := range out.Users {
		fmt.Printf("%-20s subject=%-20s groups=%v\n", u.Username, u.Subject, strings.Join(u.Groups, ","))
	}
	return nil
}

func userRemove(args []string) error {
	cf := &clientFlags{}
	fs := flag.NewFlagSet("user rm", flag.ExitOnError)
	cf.register(fs)
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: signet user rm <username>")
	}
	name := fs.Arg(0)
	data, status, err := cf.doRequest(http.MethodDelete, "/admin/users/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return adminResponseError(status, data)
	}
	fmt.Printf("Removed user %s\n", name)
	return nil
}

// --- client subcommands ---

func runClient(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: signet client <add|list|rm> ...")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add":
		return clientAdd(rest)
	case "list":
		return clientList(rest)
	case "rm", "remove", "delete":
		return clientRemove(rest)
	default:
		return fmt.Errorf("unknown client subcommand %q", sub)
	}
}

func clientAdd(args []string) error {
	cf := &clientFlags{}
	fs := flag.NewFlagSet("client add", flag.ExitOnError)
	cf.register(fs)
	redirectList := &stringSlice{}
	fs.Var(redirectList, "redirect-url", "Redirect URL (repeatable)")
	subject := fs.String("subject", "", "Subject for client_credentials (defaults to id)")
	groups := fs.String("groups", "", "Comma-separated groups")
	secret := fs.String("secret", "", "Client secret (generated if empty)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: signet client add <id> [--redirect-url URL] [--subject S] [--groups a,b] [--secret X]")
	}
	id := fs.Arg(0)
	redirects := append([]string{}, *redirectList...)
	var g []string
	if *groups != "" {
		for _, part := range strings.Split(*groups, ",") {
			if part = strings.TrimSpace(part); part != "" {
				g = append(g, part)
			}
		}
	}
	data, status, err := cf.doRequest(http.MethodPost, "/admin/clients", clientRequest{ID: id, Secret: *secret, Subject: *subject, Groups: g, RedirectURLs: redirects})
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return adminResponseError(status, data)
	}
	var out struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(data, &out)
	fmt.Printf("Created client %s\n", out.ID)
	fmt.Printf("Secret: %s\n", out.Secret)
	fmt.Println("Store this secret now; it is only shown once.")
	return nil
}

func clientList(args []string) error {
	cf := &clientFlags{}
	fs := flag.NewFlagSet("client list", flag.ExitOnError)
	cf.register(fs)
	fs.Parse(args)
	data, status, err := cf.doRequest(http.MethodGet, "/admin/clients", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return adminResponseError(status, data)
	}
	var out struct {
		Clients []Client `json:"clients"`
	}
	_ = json.Unmarshal(data, &out)
	if len(out.Clients) == 0 {
		fmt.Println("No clients.")
		return nil
	}
	for _, c := range out.Clients {
		kind := "confidential"
		if c.Secret == "" {
			kind = "public"
		}
		fmt.Printf("%-20s %-13s redirects=%v\n", c.ID, kind, c.RedirectURLs)
	}
	return nil
}

func clientRemove(args []string) error {
	cf := &clientFlags{}
	fs := flag.NewFlagSet("client rm", flag.ExitOnError)
	cf.register(fs)
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: signet client rm <id>")
	}
	id := fs.Arg(0)
	data, status, err := cf.doRequest(http.MethodDelete, "/admin/clients/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return adminResponseError(status, data)
	}
	fmt.Printf("Removed client %s\n", id)
	return nil
}

// adminResponseError turns a non-2xx admin response into an error.
func adminResponseError(status int, data []byte) error {
	var out struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &out) == nil && out.Error != "" {
		return fmt.Errorf("HTTP %d: %s", status, out.Error)
	}
	return fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(data)))
}

// stringSlice is a repeatable string flag.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}
