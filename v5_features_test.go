package fsa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// --- crypto/rand OTP ---

func TestGenerateCode_FormatAndUniqueness(t *testing.T) {
	digitRe := regexp.MustCompile(`^\d{6}$`)
	seen := make(map[string]int)
	const N = 5000
	for i := 0; i < N; i++ {
		c, err := generateCode()
		if err != nil {
			t.Fatalf("generateCode error: %v", err)
		}
		if !digitRe.MatchString(c) {
			t.Fatalf("generateCode = %q, want 6 digits", c)
		}
		seen[c]++
	}
	// With crypto/rand over 10^6 space and 5000 draws, an upper bound on the
	// most-repeated value is generous at 5 — the time-seeded math/rand
	// version would routinely produce collisions far above this.
	for code, count := range seen {
		if count > 5 {
			t.Fatalf("code %s drawn %d times, randomness looks broken", code, count)
		}
	}
}

// --- refresh-token rotation ---

func TestRefreshToken_RejectsReplay(t *testing.T) {
	auth := createTestAuth()

	userID := uuid.New()
	rt, jti, exp, err := createRefreshToken(userID, "rotate@example.com", auth.Cfg.RefreshTokenSecret, auth.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := auth.RefreshTokenStore.MarkIssued(context.Background(), jti, userID, exp); err != nil {
		t.Fatalf("mark issued: %v", err)
	}

	if _, err := auth.RefreshToken(context.Background(), rt.Token); err != nil {
		t.Fatalf("first use unexpectedly failed: %v", err)
	}

	_, err = auth.RefreshToken(context.Background(), rt.Token)
	if err == nil {
		t.Fatal("expected replay of refresh token to be rejected")
	}
	if !strings.Contains(err.Error(), "already used") {
		t.Errorf("expected 'already used' error, got: %v", err)
	}
}

func TestRefreshToken_RejectsUnknownJTI(t *testing.T) {
	auth := createTestAuth()

	// Mint a refresh token but never call MarkIssued — store treats it as unknown.
	rt, _, _, err := createRefreshToken(uuid.New(), "ghost@example.com", auth.Cfg.RefreshTokenSecret, auth.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if _, err := auth.RefreshToken(context.Background(), rt.Token); err == nil {
		t.Fatal("expected refresh with unknown jti to be rejected")
	}
}

// --- EnrichClaims hook ---

func TestEnrichClaims_MergesExtraClaims(t *testing.T) {
	cfg := &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "test-access-secret",
		RefreshTokenSecret:         "test-refresh-secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		EnrichClaims: func(ctx context.Context, id uuid.UUID, email string) (map[string]any, error) {
			return map[string]any{
				"role":  "admin",
				"org":   "acme",
				"id":    "ATTACKER", // base claim — must be ignored
				"email": "attacker@evil.com",
				"exp":   1,
			}, nil
		},
	}
	auth := createTestAuthWithConfig(cfg)

	email := "claims@example.com"
	if err := auth.Db.StoreVerificationCode(email, "123456", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("store code: %v", err)
	}

	ok, tokens, err := auth.LoginStep2ConfirmCode(context.Background(), email, "123456")
	if err != nil || !ok {
		t.Fatalf("confirm: ok=%v err=%v", ok, err)
	}

	parsed, err := jwt.Parse(tokens.AccessToken.Token, func(t *jwt.Token) (interface{}, error) {
		return []byte(cfg.AccessTokenSecret), nil
	})
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	if claims["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", claims["role"])
	}
	if claims["org"] != "acme" {
		t.Errorf("expected org=acme, got %v", claims["org"])
	}
	if claims["id"] == "ATTACKER" {
		t.Error("EnrichClaims must not be able to overwrite id")
	}
	if claims["email"] == "attacker@evil.com" {
		t.Error("EnrichClaims must not be able to overwrite email")
	}
	if claims["email"] != email {
		t.Errorf("expected email=%s, got %v", email, claims["email"])
	}
	// exp must reflect AccessTokenValidityPeriod (~1h from now), not 1.
	expFloat, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp claim has wrong type %T", claims["exp"])
	}
	if int64(expFloat) <= time.Now().Add(30*time.Minute).Unix() {
		t.Errorf("exp claim was overwritten or too small: %v", expFloat)
	}
}

func TestEnrichClaims_ErrorPropagates(t *testing.T) {
	cfg := &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "test-access-secret",
		RefreshTokenSecret:         "test-refresh-secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		EnrichClaims: func(ctx context.Context, id uuid.UUID, email string) (map[string]any, error) {
			return nil, errEnrichFail
		},
	}
	auth := createTestAuthWithConfig(cfg)

	email := "claims-fail@example.com"
	if err := auth.Db.StoreVerificationCode(email, "123456", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("store code: %v", err)
	}

	_, _, err := auth.LoginStep2ConfirmCode(context.Background(), email, "123456")
	if err == nil {
		t.Fatal("expected EnrichClaims error to propagate")
	}
	if !strings.Contains(err.Error(), "enrich claims") {
		t.Errorf("expected wrapped enrich error, got: %v", err)
	}
}

// --- Config.Prefix ---

func TestPrefix_MountsAtCustomPath(t *testing.T) {
	cfg := &Config{
		AppName:                    "TestApp",
		Prefix:                     "/api/v1/auth",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "test-access-secret",
		RefreshTokenSecret:         "test-refresh-secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	auth := createTestAuthWithConfig(cfg)
	r := chi.NewRouter()
	NewHandler(r, auth)

	body := `{"email":"test@example.com","returnUrl":"https://app.com/login"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on custom prefix, got %d: %s", w.Code, w.Body.String())
	}

	// Default /auth/login must NOT be mounted when a custom prefix is set.
	req2 := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code == http.StatusOK {
		t.Errorf("expected default /auth/login to be unmounted, got 200")
	}
}

func TestPrefix_RefreshCookiePathDefaultsFromPrefix(t *testing.T) {
	cfg := &Config{
		AppName:                    "TestApp",
		Prefix:                     "/api/v1/auth",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "test-access-secret",
		RefreshTokenSecret:         "test-refresh-secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	}
	auth := createTestAuthWithConfig(cfg)

	email := "cookie@example.com"
	if err := auth.Db.StoreVerificationCode(email, "123456", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("store: %v", err)
	}
	ok, tokens, err := auth.LoginStep2ConfirmCode(context.Background(), email, "123456")
	if err != nil || !ok {
		t.Fatalf("confirm: %v / %v", ok, err)
	}

	w := httptest.NewRecorder()
	auth.SetTokenCookies(w, tokens)

	cookie := findCookie(w.Result().Cookies(), "refresh_token")
	if cookie == nil {
		t.Fatal("missing refresh_token cookie")
	}
	if cookie.Path != "/api/v1/auth/refresh" {
		t.Errorf("expected refresh cookie path /api/v1/auth/refresh, got %s", cookie.Path)
	}
}

// --- Per-email rate limiting ---

func TestLogin_PerEmailRateLimit(t *testing.T) {
	cfg := &Config{
		AppName:                       "TestApp",
		ReturnUrls:                    []string{"https://app.com/login"},
		AccessTokenSecret:             "secret",
		RefreshTokenSecret:            "secret",
		CodeValidityPeriod:            5 * time.Minute,
		AccessTokenValidityPeriod:     1 * time.Hour,
		RefreshTokenValidityPeriod:    24 * time.Hour,
		LoginRateLimitPerEmailPerHour: 3,
	}
	auth := createTestAuthWithConfig(cfg)
	r := chi.NewRouter()
	NewHandler(r, auth)

	post := func() int {
		body := `{"email":"flood@example.com","returnUrl":"https://app.com/login"}`
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := 0; i < 3; i++ {
		if code := post(); code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Errorf("4th attempt: expected 429, got %d", code)
	}
}

// --- CORS middleware ---

func TestCORS_AddsHeadersOnPreflight(t *testing.T) {
	cfg := &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
		CORSConfig: &CORSConfig{
			AllowedOrigins:   []string{"https://app.example.com"},
			AllowCredentials: true,
		},
	}
	auth := createTestAuthWithConfig(cfg)
	r := chi.NewRouter()
	NewHandler(r, auth)

	req := httptest.NewRequest(http.MethodOptions, "/auth/login", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("expected Allow-Origin echo, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("expected Allow-Credentials true, got %q", got)
	}
}

// --- shared test fixtures ---

var errEnrichFail = &stringErr{"enrich exploded"}

type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }

// Ensure the mem store handles its happy path so the integration tests above
// have stable foundations.
func TestMemRefreshTokenStore_MarkUsedTwice(t *testing.T) {
	s := NewMemRefreshTokenStore()
	jti := "abc"
	if err := s.MarkIssued(context.Background(), jti, uuid.New(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	used, err := s.MarkUsed(context.Background(), jti)
	if err != nil || used {
		t.Fatalf("first MarkUsed: used=%v err=%v", used, err)
	}
	used, err = s.MarkUsed(context.Background(), jti)
	if err != nil || !used {
		t.Fatalf("second MarkUsed: used=%v err=%v", used, err)
	}
}

func TestMemRefreshTokenStore_ExpiredEntryRejected(t *testing.T) {
	s := NewMemRefreshTokenStore()
	jti := "expired"
	if err := s.MarkIssued(context.Background(), jti, uuid.New(), time.Now().Add(-1*time.Minute)); err != nil {
		t.Fatal(err)
	}
	used, err := s.MarkUsed(context.Background(), jti)
	if err != nil || !used {
		t.Fatalf("expected expired entry to be rejected: used=%v err=%v", used, err)
	}
}
