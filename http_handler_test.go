package fsa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func createTestHandler() (*Handler, *Auth) {
	auth := createTestAuth()
	r := chi.NewRouter()
	h := NewHandler(r, auth)
	return h, auth
}

func createTestHandlerWithRouter() (http.Handler, *Auth) {
	auth := createTestAuth()
	r := chi.NewRouter()
	NewHandler(r, auth)
	return r, auth
}

// Phase 2: POST Refresh Tests

func TestRefreshToken_POSTMethod(t *testing.T) {
	router, auth := createTestHandlerWithRouter()

	// First, create a valid refresh token
	refreshToken, err := createRefreshToken(
		mustParseUUID("550e8400-e29b-41d4-a716-446655440000"),
		"test@example.com",
		auth.Cfg.RefreshTokenSecret,
		auth.Cfg.RefreshTokenValidityPeriod,
	)
	if err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	body := `{"token": "` + refreshToken.Token + `"}`
	req := httptest.NewRequest("POST", "/auth/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}

	// Verify cookies are set
	cookies := w.Result().Cookies()
	if len(cookies) < 2 {
		t.Errorf("expected at least 2 cookies, got %d", len(cookies))
	}

	accessCookie := findCookie(cookies, "access_token")
	if accessCookie == nil {
		t.Error("expected access_token cookie")
	}

	refreshCookie := findCookie(cookies, "refresh_token")
	if refreshCookie == nil {
		t.Error("expected refresh_token cookie")
	}
}

func TestRefreshToken_POSTRejectsEmptyBody(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("POST", "/auth/refresh", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", w.Code)
	}
}

func TestRefreshToken_POSTRejectsInvalidJSON(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("POST", "/auth/refresh", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", w.Code)
	}
}

func TestRefreshToken_GETMethodReturns405(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("GET", "/auth/refresh?token=valid_token", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status MethodNotAllowed (405), got %d", w.Code)
	}
}

// Phase 3: Cookie Tests in Handler

func TestConfirmCode_SetsCookiesAndCSRFToken(t *testing.T) {
	router, auth := createTestHandlerWithRouter()

	// Store a verification code
	email := "test@example.com"
	code := "123456"
	err := auth.Db.StoreVerificationCode(email, code, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("failed to store verification code: %v", err)
	}

	req := httptest.NewRequest("GET", "/auth/confirm?code="+code+"&email="+email, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()

	// Should have access_token, refresh_token, and csrf_token
	accessCookie := findCookie(cookies, "access_token")
	if accessCookie == nil {
		t.Error("expected access_token cookie")
	}

	refreshCookie := findCookie(cookies, "refresh_token")
	if refreshCookie == nil {
		t.Error("expected refresh_token cookie")
	}

	csrfCookie := findCookie(cookies, "csrf_token")
	if csrfCookie == nil {
		t.Error("expected csrf_token cookie")
	}

	// Response body should NOT contain tokens, just status
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if response["status"] != "authenticated" {
		t.Errorf("expected status 'authenticated', got %s", response["status"])
	}
}

func TestLogout_ClearsCookies(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	cookies := w.Result().Cookies()

	// All cookies should be expired
	for _, cookie := range cookies {
		if cookie.MaxAge != -1 {
			t.Errorf("expected cookie %s to have MaxAge -1, got %d", cookie.Name, cookie.MaxAge)
		}
	}
}

func mustParseUUID(s string) (id [16]byte) {
	// Simple UUID parsing for testing
	s = strings.ReplaceAll(s, "-", "")
	for i := 0; i < 16; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				b = b*16 + c - '0'
			case c >= 'a' && c <= 'f':
				b = b*16 + c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b = b*16 + c - 'A' + 10
			}
		}
		id[i] = b
	}
	return
}
