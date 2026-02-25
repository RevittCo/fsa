package fsa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetTokenCookies_SetsAccessTokenCookie(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode},
	})

	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: time.Now().Add(24 * time.Hour)},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	accessCookie := findCookie(cookies, "access_token")

	if accessCookie == nil {
		t.Fatal("expected access_token cookie")
	}
	if accessCookie.Value != "access123" {
		t.Errorf("expected value 'access123', got '%s'", accessCookie.Value)
	}
	if !accessCookie.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
	if !accessCookie.Secure {
		t.Error("expected Secure to be true")
	}
	if accessCookie.Path != "/" {
		t.Errorf("expected path '/', got '%s'", accessCookie.Path)
	}
}

func TestSetTokenCookies_SetsRefreshTokenWithRestrictedPath(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Secure: true},
	})

	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: time.Now().Add(24 * time.Hour)},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	refreshCookie := findCookie(cookies, "refresh_token")

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if refreshCookie.Path != "/auth/refresh" {
		t.Errorf("expected path '/auth/refresh', got '%s'", refreshCookie.Path)
	}
	if !refreshCookie.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
}

func TestSetTokenCookies_UsesSecureDefaultsWhenConfigNil(t *testing.T) {
	auth := createTestAuth() // No CookieConfig

	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: time.Now().Add(24 * time.Hour)},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	accessCookie := findCookie(cookies, "access_token")

	if accessCookie == nil {
		t.Fatal("expected access_token cookie")
	}
	if !accessCookie.Secure {
		t.Error("expected Secure to be true by default")
	}
	if !accessCookie.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
}

func TestSetTokenCookies_SetsDomain(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Domain: ".example.com", Secure: true},
	})

	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: time.Now().Add(24 * time.Hour)},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	accessCookie := findCookie(cookies, "access_token")

	if accessCookie == nil {
		t.Fatal("expected access_token cookie")
	}
	// Go's http package normalizes domain by removing leading dot
	if accessCookie.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got '%s'", accessCookie.Domain)
	}
}

func TestClearTokenCookies_UsesCorrectPaths(t *testing.T) {
	auth := createTestAuth()

	w := httptest.NewRecorder()
	auth.ClearTokenCookies(w)

	cookies := w.Result().Cookies()
	accessCookie := findCookie(cookies, "access_token")
	refreshCookie := findCookie(cookies, "refresh_token")

	if accessCookie == nil {
		t.Fatal("expected access_token cookie")
	}
	if accessCookie.Path != "/" {
		t.Errorf("expected access_token path '/', got '%s'", accessCookie.Path)
	}

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if refreshCookie.Path != "/auth/refresh" {
		t.Errorf("expected refresh_token path '/auth/refresh', got '%s'", refreshCookie.Path)
	}
}

func TestClearTokenCookies_UsesSecureDefaultsWhenConfigNil(t *testing.T) {
	auth := createTestAuth() // No CookieConfig

	w := httptest.NewRecorder()
	auth.ClearTokenCookies(w)

	cookies := w.Result().Cookies()
	accessCookie := findCookie(cookies, "access_token")
	refreshCookie := findCookie(cookies, "refresh_token")

	if accessCookie == nil {
		t.Fatal("expected access_token cookie")
	}
	if !accessCookie.Secure {
		t.Error("expected access_token Secure to be true by default")
	}

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if !refreshCookie.Secure {
		t.Error("expected refresh_token Secure to be true by default")
	}
}

func TestSetTokenCookies_SetsRefreshTokenExpiry(t *testing.T) {
	auth := createTestAuth()

	expiry := time.Now().Add(24 * time.Hour)
	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: expiry},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	refreshCookie := findCookie(cookies, "refresh_token")

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	// Allow 1 second tolerance for test execution time
	diff := refreshCookie.Expires.Sub(expiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected refresh_token Expires close to %v, got %v", expiry, refreshCookie.Expires)
	}
}

func TestSetTokenCookies_SetsRefreshTokenSecureAndDomain(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Domain: ".example.com", Secure: true},
	})

	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: time.Now().Add(24 * time.Hour)},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	refreshCookie := findCookie(cookies, "refresh_token")

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if !refreshCookie.Secure {
		t.Error("expected refresh_token Secure to be true")
	}
	if refreshCookie.Domain != "example.com" {
		t.Errorf("expected refresh_token domain 'example.com', got '%s'", refreshCookie.Domain)
	}
}

func TestSetTokenCookies_UsesCustomRefreshPath(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Secure: true, RefreshPath: "/api/v1/auth/refresh"},
	})

	tokens := &TokenResponse{
		AccessToken:  &Token{Token: "access123", TokenExpiry: time.Now().Add(time.Hour)},
		RefreshToken: &Token{Token: "refresh123", TokenExpiry: time.Now().Add(24 * time.Hour)},
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookies := w.Result().Cookies()
	refreshCookie := findCookie(cookies, "refresh_token")

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if refreshCookie.Path != "/api/v1/auth/refresh" {
		t.Errorf("expected path '/api/v1/auth/refresh', got '%s'", refreshCookie.Path)
	}
}

func TestClearTokenCookies_UsesCustomRefreshPath(t *testing.T) {
	auth := createTestAuthWithConfig(&Config{
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CookieConfig:               &CookieConfig{Secure: true, RefreshPath: "/api/v1/auth/refresh"},
	})

	w := httptest.NewRecorder()
	auth.ClearTokenCookies(w)

	cookies := w.Result().Cookies()
	refreshCookie := findCookie(cookies, "refresh_token")

	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if refreshCookie.Path != "/api/v1/auth/refresh" {
		t.Errorf("expected path '/api/v1/auth/refresh', got '%s'", refreshCookie.Path)
	}
}

func TestClearTokenCookies_ExpiresAllTokenCookies(t *testing.T) {
	auth := createTestAuth()

	w := httptest.NewRecorder()
	auth.ClearTokenCookies(w)

	cookies := w.Result().Cookies()

	if len(cookies) < 2 {
		t.Errorf("expected at least 2 cookies, got %d", len(cookies))
	}

	for _, cookie := range cookies {
		if cookie.MaxAge != -1 {
			t.Errorf("expected cookie %s to have MaxAge -1, got %d", cookie.Name, cookie.MaxAge)
		}
		if !cookie.Expires.Before(time.Now()) {
			t.Errorf("expected cookie %s to be expired", cookie.Name)
		}
	}
}
