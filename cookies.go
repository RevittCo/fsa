package fsa

import (
	"net/http"
	"time"
)

func (a *Auth) SetTokenCookies(w http.ResponseWriter, tokens *TokenResponse) {
	cfg := a.Cfg.CookieConfig
	if cfg == nil {
		cfg = &CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode}
	}

	refreshPath := cfg.RefreshPath
	if refreshPath == "" {
		refreshPath = "/auth/refresh"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken.Token,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Path:     "/",
		Expires:  tokens.AccessToken.TokenExpiry,
		Domain:   cfg.Domain,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken.Token,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Path:     refreshPath,
		Expires:  tokens.RefreshToken.TokenExpiry,
		Domain:   cfg.Domain,
	})
}

func (a *Auth) ClearTokenCookies(w http.ResponseWriter) {
	cfg := a.Cfg.CookieConfig
	if cfg == nil {
		cfg = &CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode}
	}

	refreshPath := cfg.RefreshPath
	if refreshPath == "" {
		refreshPath = "/auth/refresh"
	}

	expired := time.Now().Add(-24 * time.Hour)

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Path:     "/",
		Expires:  expired,
		MaxAge:   -1,
		Domain:   cfg.Domain,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Path:     refreshPath,
		Expires:  expired,
		MaxAge:   -1,
		Domain:   cfg.Domain,
	})
}
