package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// adminHandler returns the /admin/ mux, gated by the management Bearer token.
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/users", s.adminUsers)
	mux.HandleFunc("/admin/users/", s.adminUserByName)
	mux.HandleFunc("/admin/clients", s.adminClients)
	mux.HandleFunc("/admin/clients/", s.adminClientByID)
	return mux
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.HasPrefix(header, prefix) {
		s.adminError(w, http.StatusUnauthorized, "missing bearer token")
		return false
	}
	token := strings.TrimPrefix(header, prefix)
	if !s.store.CheckAdminToken(token) {
		s.adminError(w, http.StatusUnauthorized, "invalid admin token")
		return false
	}
	return true
}

func (s *Server) adminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type userRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

// adminUsers handles GET (list) and POST (create) /admin/users.
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.json(w, map[string]any{"users": s.store.ListUsers()})
	case http.MethodPost:
		var req userRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
			s.adminError(w, http.StatusBadRequest, "username is required")
			return
		}
		user, _, err := s.store.AddUser(User{Username: req.Username, Password: req.Password, Name: req.Name, Email: req.Email, Groups: req.Groups})
		if err != nil {
			s.adminError(w, http.StatusConflict, err.Error())
			return
		}
		w.WriteHeader(http.StatusCreated)
		s.json(w, map[string]any{"username": user.Username, "password": user.Password})
	default:
		s.adminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// adminUserByName handles PATCH and DELETE /admin/users/{name}.
func (s *Server) adminUserByName(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Groups   []string `json:"groups"`
			Password string   `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.adminError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		user, err := s.store.UpdateUser(name, req.Groups, req.Password)
		if err != nil {
			s.adminError(w, http.StatusNotFound, err.Error())
			return
		}
		resp := map[string]any{"username": user.Username, "groups": user.Groups}
		if req.Password != "" {
			resp["password"] = user.Password
		}
		s.json(w, resp)
	case http.MethodDelete:
		if err := s.store.RemoveUser(name); err != nil {
			s.adminError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.adminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type clientRequest struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	Subject      string   `json:"subject"`
	Groups       []string `json:"groups"`
	RedirectURLs []string `json:"redirect_urls"`
}

// adminClients handles GET (list) and POST (create) /admin/clients.
func (s *Server) adminClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.json(w, map[string]any{"clients": s.store.ListClients()})
	case http.MethodPost:
		var req clientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			s.adminError(w, http.StatusBadRequest, "id is required")
			return
		}
		client, _, err := s.store.AddClient(Client{ID: req.ID, Secret: req.Secret, Subject: req.Subject, Groups: req.Groups, RedirectURLs: req.RedirectURLs})
		if err != nil {
			s.adminError(w, http.StatusConflict, err.Error())
			return
		}
		w.WriteHeader(http.StatusCreated)
		s.json(w, map[string]any{"id": client.ID, "secret": client.Secret})
	default:
		s.adminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// adminClientByID handles DELETE /admin/clients/{id}.
func (s *Server) adminClientByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/clients/")
	switch r.Method {
	case http.MethodDelete:
		if err := s.store.RemoveClient(id); err != nil {
			s.adminError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.adminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
