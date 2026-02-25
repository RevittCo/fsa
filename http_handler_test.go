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

// Login handler tests

func TestLogin_SendsVerificationCode(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	body := `{"email":"test@example.com","returnUrl":"https://app.com/login"}`
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}

	var response string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if response != "ok" {
		t.Errorf("expected response 'ok', got '%s'", response)
	}
}

func TestLogin_RejectsMissingEmail(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	body := `{"returnUrl":"https://app.com/login"}`
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", w.Code)
	}
}

func TestLogin_RejectsInvalidReturnUrl(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	body := `{"email":"test@example.com","returnUrl":"https://evil.com/login"}`
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", w.Code)
	}
}

func TestLogin_DefaultsReturnUrl(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	body := `{"email":"test@example.com"}`
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_RejectsGET(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("GET", "/auth/login?email=test@example.com", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status MethodNotAllowed (405), got %d", w.Code)
	}
}

// ConfirmCode handler tests

func TestConfirmCode_RejectsMissingParams(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	body := `{}`
	req := httptest.NewRequest("POST", "/auth/confirm", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", w.Code)
	}
}

func TestConfirmCode_RejectsWrongCode(t *testing.T) {
	router, auth := createTestHandlerWithRouter()

	email := "test@example.com"
	err := auth.Db.StoreVerificationCode(email, "123456", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("failed to store verification code: %v", err)
	}

	body := `{"code":"000000","email":"` + email + `"}`
	req := httptest.NewRequest("POST", "/auth/confirm", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConfirmCode_RejectsGET(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("GET", "/auth/confirm?code=123456&email=test@example.com", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status MethodNotAllowed (405), got %d", w.Code)
	}
}

// RefreshToken handler tests

func TestRefreshToken_RejectsExpiredToken(t *testing.T) {
	router, auth := createTestHandlerWithRouter()

	expiredToken, err := createRefreshToken(
		mustParseUUID("550e8400-e29b-41d4-a716-446655440000"),
		"test@example.com",
		auth.Cfg.RefreshTokenSecret,
		-1*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: expiredToken.Token})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRefreshToken_POSTMethod(t *testing.T) {
	router, auth := createTestHandlerWithRouter()

	refreshToken, err := createRefreshToken(
		mustParseUUID("550e8400-e29b-41d4-a716-446655440000"),
		"test@example.com",
		auth.Cfg.RefreshTokenSecret,
		auth.Cfg.RefreshTokenValidityPeriod,
	)
	if err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken.Token})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}

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

func TestRefreshToken_RejectsNoCookie(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status Unauthorized (401), got %d", w.Code)
	}
}

func TestRefreshToken_RejectsInvalidCookie(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "not-a-valid-jwt"})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status Unauthorized (401), got %d", w.Code)
	}
}

func TestRefreshToken_GETMethodReturns405(t *testing.T) {
	router, _ := createTestHandlerWithRouter()

	req := httptest.NewRequest("GET", "/auth/refresh", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status MethodNotAllowed (405), got %d", w.Code)
	}
}

// Cookie Tests in Handler

func TestConfirmCode_SetsCookiesAndCSRFToken(t *testing.T) {
	router, auth := createTestHandlerWithRouter()

	email := "test@example.com"
	code := "123456"
	err := auth.Db.StoreVerificationCode(email, code, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("failed to store verification code: %v", err)
	}

	body := `{"code":"` + code + `","email":"` + email + `"}`
	req := httptest.NewRequest("POST", "/auth/confirm", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()

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

	for _, cookie := range cookies {
		if cookie.MaxAge != -1 {
			t.Errorf("expected cookie %s to have MaxAge -1, got %d", cookie.Name, cookie.MaxAge)
		}
	}
}

func mustParseUUID(s string) (id [16]byte) {
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
