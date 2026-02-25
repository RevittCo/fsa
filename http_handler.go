package fsa

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth_chi"
	"github.com/go-chi/chi/v5"
)

type Handler struct {
	auth *Auth
}

func NewHandler(r chi.Router, auth *Auth) *Handler {
	h := &Handler{
		auth: auth,
	}
	h.SetupRoutes(r)
	return h
}

func (h *Handler) SetupRoutes(router chi.Router) {
	fmt.Println("setting up routes for auth")

	limiter := tollbooth.NewLimiter(float64(h.auth.Cfg.RateLimitPerSecond), nil)
	limiter.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"})

	router.Group(func(r chi.Router) {
		if h.auth.Cfg.RateLimitPerSecond > 0 {
			r.Use(tollbooth_chi.LimitHandler(limiter))
		}
		r.Post("/auth/login", h.Login)
		r.Post("/auth/confirm", h.ConfirmCode)
		r.Post("/auth/refresh", h.RefreshToken)
		r.Post("/auth/logout", h.Logout)
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email     string `json:"email"`
		ReturnUrl string `json:"returnUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErr(w, fmt.Errorf("invalid request body"), http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if len(req.Email) == 0 {
		WriteErr(w, fmt.Errorf("email required"), http.StatusBadRequest)
		return
	}

	if len(req.ReturnUrl) == 0 {
		req.ReturnUrl = h.auth.Cfg.ReturnUrls[0]
	}

	validReturnUrl := false
	for _, url := range h.auth.Cfg.ReturnUrls {
		if url == req.ReturnUrl {
			validReturnUrl = true
			break
		}
	}

	if !validReturnUrl {
		WriteErr(w, fmt.Errorf("invalid return url"), http.StatusBadRequest)
		return
	}

	err := h.auth.LoginStep1SendVerificationCode(ctx, req.Email, req.ReturnUrl)
	if err != nil {
		WriteErr(w, err, http.StatusInternalServerError)
		return
	}

	WriteJSON(w, "ok")
}

func (h *Handler) ConfirmCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code  string `json:"code"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErr(w, fmt.Errorf("invalid request body"), http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	if len(req.Code) == 0 || len(req.Email) == 0 {
		WriteErr(w, fmt.Errorf("code and email required"), http.StatusBadRequest)
		return
	}

	confirmed, tokens, err := h.auth.LoginStep2ConfirmCode(ctx, req.Email, req.Code)
	if err != nil {
		WriteErr(w, err, http.StatusInternalServerError)
		return
	}

	if !confirmed {
		WriteErr(w, fmt.Errorf("error confirming code"), http.StatusBadRequest)
		return
	}

	h.auth.SetTokenCookies(w, tokens)
	h.auth.SetCSRFCookie(w)
	WriteJSON(w, map[string]string{"status": "authenticated"})
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		WriteErr(w, fmt.Errorf("refresh token required"), http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	tokens, err := h.auth.RefreshToken(ctx, cookie.Value)
	if err != nil {
		WriteErr(w, err, http.StatusUnauthorized)
		return
	}

	h.auth.SetTokenCookies(w, tokens)
	WriteJSON(w, map[string]string{"status": "refreshed"})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.auth.ClearTokenCookies(w)
	WriteJSON(w, map[string]string{"status": "logged_out"})
}
