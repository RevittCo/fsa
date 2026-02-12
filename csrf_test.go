package fsa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCSRFMiddleware_AllowsGETRequests(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("GET", "/api/data", nil)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK for GET request, got %d", w.Code)
	}
}

func TestCSRFMiddleware_AllowsHEADRequests(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("HEAD", "/api/data", nil)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK for HEAD request, got %d", w.Code)
	}
}

func TestCSRFMiddleware_AllowsOPTIONSRequests(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("OPTIONS", "/api/data", nil)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK for OPTIONS request, got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksPOSTWithoutToken(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("POST", "/api/data", nil)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden for POST without token, got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksPUTWithoutToken(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("PUT", "/api/data", nil)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden for PUT without token, got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksDELETEWithoutToken(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("DELETE", "/api/data", nil)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden for DELETE without token, got %d", w.Code)
	}
}

func TestCSRFMiddleware_AllowsPOSTWithMatchingToken(t *testing.T) {
	auth := createTestAuth()

	token := "valid-csrf-token-123"
	req := httptest.NewRequest("POST", "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK with matching token, got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksMismatchedToken(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("POST", "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	req.Header.Set("X-CSRF-Token", "different-token")
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden with mismatched token, got %d", w.Code)
	}
}

func TestCSRFMiddleware_BlocksMissingHeader(t *testing.T) {
	auth := createTestAuth()

	req := httptest.NewRequest("POST", "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	// No header set
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status Forbidden with missing header, got %d", w.Code)
	}
}

func TestSetCSRFCookie_SetsReadableCookie(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode},
	})

	w := httptest.NewRecorder()
	token := auth.SetCSRFCookie(w)

	cookies := w.Result().Cookies()
	csrfCookie := findCookie(cookies, "csrf_token")

	if csrfCookie == nil {
		t.Fatal("expected csrf_token cookie")
	}
	if csrfCookie.Value != token {
		t.Errorf("expected cookie value to match returned token")
	}
	if csrfCookie.HttpOnly {
		t.Error("expected HttpOnly to be false (JS needs to read this)")
	}
	if !csrfCookie.Secure {
		t.Error("expected Secure to be true")
	}
}

func TestSetCSRFCookie_UsesDefaultsWhenConfigNil(t *testing.T) {
	auth := createTestAuth() // No CSRFConfig

	w := httptest.NewRecorder()
	token := auth.SetCSRFCookie(w)

	if token == "" {
		t.Error("expected non-empty token")
	}

	cookies := w.Result().Cookies()
	csrfCookie := findCookie(cookies, "csrf_token")

	if csrfCookie == nil {
		t.Fatal("expected csrf_token cookie with default name")
	}
}

func TestGenerateCSRFToken_ReturnsUniqueTokens(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := generateCSRFToken(32)
		if tokens[token] {
			t.Error("generated duplicate token")
		}
		tokens[token] = true
	}
}

func TestGenerateCSRFToken_ReturnsNonEmptyToken(t *testing.T) {
	token := generateCSRFToken(32)
	if token == "" {
		t.Error("expected non-empty token")
	}
	// Base64 encoded 32 bytes should be ~43 characters
	if len(token) < 40 {
		t.Errorf("expected token length >= 40, got %d", len(token))
	}
}

func TestCSRFMiddleware_UsesCustomConfig(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CSRFConfig: &CSRFConfig{
			CookieName:  "custom_csrf",
			HeaderName:  "X-Custom-CSRF",
			TokenLength: 64,
		},
	})

	token := "valid-csrf-token-123"
	req := httptest.NewRequest("POST", "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "custom_csrf", Value: token})
	req.Header.Set("X-Custom-CSRF", token)
	w := httptest.NewRecorder()

	handler := auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK with custom config, got %d", w.Code)
	}
}
