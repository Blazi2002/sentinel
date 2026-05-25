package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// apiServer exposes the hub's data over HTTP for the operator dashboard.
type apiServer struct {
	store *Store
	log   *slog.Logger
}

// newAPIServer builds an HTTP API server.
func newAPIServer(store *Store, log *slog.Logger) *apiServer {
	return &apiServer{store: store, log: log}
}

// routes builds the HTTP handler with all API routes registered.
func (a *apiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/incidents", a.handleListIncidents)
	mux.HandleFunc("GET /api/incidents/{id}", a.handleGetIncident)
	mux.HandleFunc("POST /api/incidents/{id}/decision", a.handleDecision)
	// Wrap everything so the browser is allowed to call the API.
	return withCORS(mux)
}

// handleListIncidents returns all incidents as JSON, newest first.
func (a *apiServer) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	incidents, err := a.store.ListIncidents(r.Context())
	if err != nil {
		a.fail(w, "could not load incidents", err)
		return
	}
	a.writeJSON(w, incidents)
}

// handleGetIncident returns one fully-assembled incident as JSON.
func (a *apiServer) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	detail, err := a.store.GetIncidentDetail(r.Context(), id)
	if err != nil {
		a.fail(w, "could not load incident", err)
		return
	}
	a.writeJSON(w, detail)
}

// decisionRequest is the JSON body for an approve/reject action.
type decisionRequest struct {
	Decision string `json:"decision"` // "approved" or "rejected"
	Operator string `json:"operator"`
	Note     string `json:"note"`
}

// handleDecision records an operator's approve/reject choice.
func (a *apiServer) handleDecision(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}

	var req decisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Only two decisions are valid from the dashboard.
	if req.Decision != "approved" && req.Decision != "rejected" {
		http.Error(w, "decision must be 'approved' or 'rejected'",
			http.StatusBadRequest)
		return
	}

	updated, err := a.store.DecideIncident(
		r.Context(), id, req.Decision, req.Operator, req.Note)
	if err != nil {
		a.fail(w, "could not record decision", err)
		return
	}
	a.log.Info("incident decision recorded",
		"incident_id", req.Decision, "operator", req.Operator)
	a.writeJSON(w, updated)
}

// --- helpers ---

// writeJSON encodes v as JSON into the response.
func (a *apiServer) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		a.log.Error("failed to encode response", "error", err)
	}
}

// fail logs an internal error and returns a 500 to the client.
func (a *apiServer) fail(w http.ResponseWriter, msg string, err error) {
	a.log.Error(msg, "error", err)
	http.Error(w, msg, http.StatusInternalServerError)
}

// parseUUIDParam parses a UUID string from a URL path parameter.
func parseUUIDParam(s string) (pgtype.UUID, error) {
	var id pgtype.UUID
	err := id.Scan(s)
	return id, err
}

// withCORS allows the browser-based dashboard to call the API.
// In production the dashboard is served from the same origin and this
// can be tightened; for local development it keeps things simple.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startAPIServer runs the HTTP API on the given address until ctx ends.
func startAPIServer(ctx context.Context, addr string, h http.Handler, log *slog.Logger) {
	srv := &http.Server{Addr: addr, Handler: h}

	go func() {
		log.Info("HTTP API listening", "address", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("HTTP API stopped", "error", err)
		}
	}()

	// Shut down cleanly when the context ends.
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
