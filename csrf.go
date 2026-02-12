package fsa

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

func generateCSRFToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (a *Auth) SetCSRFCookie(w http.ResponseWriter) string {
	cfg := a.Cfg.CSRFConfig
	if cfg == nil {
		cfg = &CSRFConfig{
			CookieName:  "csrf_token",
			HeaderName:  "X-CSRF-Token",
			TokenLength: 32,
		}
	}

	cookieCfg := a.Cfg.CookieConfig
	if cookieCfg == nil {
		cookieCfg = &CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode}
	}

	token := generateCSRFToken(cfg.TokenLength)

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		HttpOnly: false, // JS needs to read this
		Secure:   cookieCfg.Secure,
		SameSite: cookieCfg.SameSite,
		Path:     "/",
	})
	return token
}

func (a *Auth) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		cfg := a.Cfg.CSRFConfig
		if cfg == nil {
			cfg = &CSRFConfig{
				CookieName:  "csrf_token",
				HeaderName:  "X-CSRF-Token",
				TokenLength: 32,
			}
		}

		cookie, err := r.Cookie(cfg.CookieName)
		if err != nil {
			http.Error(w, "CSRF cookie missing", http.StatusForbidden)
			return
		}

		header := r.Header.Get(cfg.HeaderName)
		if header == "" || cookie.Value != header {
			http.Error(w, "CSRF token mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
