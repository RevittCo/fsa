package fsa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddleware_AcceptsCookieAuth(t *testing.T) {
	cfg := &Config{
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	middleware := NewChiMiddleware(cfg)

	token := createValidToken("secret", "test@example.com", "user-123")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	w := httptest.NewRecorder()

	var capturedEmail interface{}
	handler := middleware.VerifyAuthenticationToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEmail = r.Context().Value(UserEmailKey)
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}
	if capturedEmail != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%v'", capturedEmail)
	}
}

func TestMiddleware_PrefersHeaderOverCookie(t *testing.T) {
	cfg := &Config{
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	middleware := NewChiMiddleware(cfg)

	headerToken := createValidToken("secret", "header@example.com", "user-1")
	cookieToken := createValidToken("secret", "cookie@example.com", "user-2")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+headerToken)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: cookieToken})
	w := httptest.NewRecorder()

	var capturedEmail interface{}
	handler := middleware.VerifyAuthenticationToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEmail = r.Context().Value(UserEmailKey)
	}))

	handler.ServeHTTP(w, req)

	if capturedEmail != "header@example.com" {
		t.Errorf("expected header email 'header@example.com' to take precedence, got '%v'", capturedEmail)
	}
}

func TestMiddleware_RejectsInvalidCookie(t *testing.T) {
	cfg := &Config{
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	middleware := NewChiMiddleware(cfg)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "invalid_token"})
	w := httptest.NewRecorder()

	handler := middleware.VerifyAuthenticationToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status Unauthorized, got %d", w.Code)
	}
}

func TestMiddleware_RejectsNoCookieOrHeader(t *testing.T) {
	cfg := &Config{
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	middleware := NewChiMiddleware(cfg)

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	handler := middleware.VerifyAuthenticationToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status Unauthorized, got %d", w.Code)
	}
}

func TestMiddleware_AcceptsValidBearerToken(t *testing.T) {
	cfg := &Config{
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	middleware := NewChiMiddleware(cfg)

	token := createValidToken("secret", "bearer@example.com", "user-456")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	var capturedEmail interface{}
	var capturedUserId interface{}
	handler := middleware.VerifyAuthenticationToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEmail = r.Context().Value(UserEmailKey)
		capturedUserId = r.Context().Value(UserIdKey)
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}
	if capturedEmail != "bearer@example.com" {
		t.Errorf("expected email 'bearer@example.com', got '%v'", capturedEmail)
	}
	if capturedUserId != "user-456" {
		t.Errorf("expected userId 'user-456', got '%v'", capturedUserId)
	}
}
