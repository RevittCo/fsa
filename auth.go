package fsa

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type IAuthDb interface {
	StoreVerificationCode(email string, code string, expiresAt time.Time) error
	GetVerificationCode(email string) (code string, expiresAt time.Time, error error)
	RemoveVerificationCode(email string) error
}

type IUserCreator interface {
	CreateEmailVerifiedUserIfNotExists(ctx context.Context, email string) (id uuid.UUID, newUser bool, err error)
}

type ICodeSender interface {
	Send(to string, subject string, body string) error
}

type IEmailValidator interface {
	Validate(email string) bool
}

type IUserIdentityVerifier interface {
	CanLogin(email string) (bool, string, error)
}

// IRefreshTokenStore tracks the lifecycle of refresh tokens by their jti claim.
// Implementations must be safe for concurrent use.
//
// Distributed implementations (Redis, SQL, etc.) must make MarkUsed
// linearizable across replicas — two concurrent MarkUsed calls for the same
// jti must agree on a single winner. Reading a stale "not used" value on a
// replica that has not yet seen a successful MarkUsed elsewhere would defeat
// replay protection.
type IRefreshTokenStore interface {
	// MarkIssued records a newly minted refresh token so it can later be
	// validated and rotated. expiresAt is the token's exp claim. The write
	// must be durable before the refresh token is returned to the client;
	// otherwise a crash after issuance leaves a valid-looking token that the
	// store has no record of and will reject as unknown.
	MarkIssued(ctx context.Context, jti string, userID uuid.UUID, expiresAt time.Time) error
	// MarkUsed atomically marks a refresh token's jti as used. It returns
	// alreadyUsed=true if the jti had been used before (replay attempt).
	// An unknown jti is treated as already-used: tokens that were never
	// issued (or that have expired and been swept) must not be honoured.
	// The check-and-set must be atomic — racing callers must see exactly one
	// alreadyUsed=false response per jti.
	MarkUsed(ctx context.Context, jti string) (alreadyUsed bool, err error)
}

type Key string

const ClaimsKey Key = "claims"
const UserEmailKey Key = "userEmail"
const UserIdKey Key = "userId"

type CookieConfig struct {
	Domain      string        // For cross-subdomain auth
	Secure      bool          // HTTPS only (default: true)
	SameSite    http.SameSite // Default: SameSiteStrictMode
	RefreshPath string        // Cookie path for refresh token. Defaults to Config.Prefix + "/refresh".
}

type CSRFConfig struct {
	CookieName  string // Default: "csrf_token"
	HeaderName  string // Default: "X-CSRF-Token"
	TokenLength int    // Default: 32
}

// CORSConfig configures CORS handling on the bundled auth routes. If nil on
// Config, no CORS middleware is installed.
type CORSConfig struct {
	AllowedOrigins   []string // exact matches; "*" disables credentials
	AllowedMethods   []string // default: GET, POST, OPTIONS
	AllowedHeaders   []string // default: Authorization, Content-Type, X-CSRF-Token
	AllowCredentials bool     // default: true
	MaxAge           int      // preflight cache seconds; default: 600
}

type Config struct {
	AppName   string
	Logo      string
	Brand     string
	BrandLink string

	// Prefix is the route prefix for the bundled auth handlers
	// (login/confirm/refresh/logout). Default: "/auth".
	Prefix string

	CodeValidityPeriod         time.Duration
	AccessTokenValidityPeriod  time.Duration
	RefreshTokenValidityPeriod time.Duration

	AccessTokenSecret  string
	RefreshTokenSecret string

	// RateLimitPerSecond is the per-IP rate limit for the bundled auth routes.
	// 0 disables the per-IP limiter.
	RateLimitPerSecond int

	// LoginRateLimitPerEmailPerHour caps how many login + confirm attempts
	// a single email address may make per rolling hour, across all IPs.
	// 0 disables per-email rate limiting.
	LoginRateLimitPerEmailPerHour int

	ReturnUrls []string

	UseIdentity bool

	CookieConfig *CookieConfig // Optional, uses secure defaults if nil
	CSRFConfig   *CSRFConfig   // Optional, uses defaults if nil
	CORSConfig   *CORSConfig   // Optional, no CORS middleware if nil

	// EnrichClaims, when set, is called when minting an access token. The
	// returned map is merged into the base claims ({id, email, exp}). The
	// base claim keys "id", "email", "exp" cannot be overwritten — colliding
	// keys in the returned map are dropped.
	EnrichClaims func(ctx context.Context, userID uuid.UUID, email string) (map[string]any, error)
}

type Token struct {
	Token       string
	TokenExpiry time.Time
}

type TokenResponse struct {
	AccessToken  *Token
	RefreshToken *Token
}

type EmailData struct {
	Link       string
	Code       string
	AppName    string
	AppNameL1  string
	AppNameEnd string
	Logo       string
	Brand      string
	BrandLink  string
}

type Auth struct {
	Db                IAuthDb
	Sender            ICodeSender
	Uc                IUserCreator
	Ev                IEmailValidator
	Uiv               IUserIdentityVerifier
	RefreshTokenStore IRefreshTokenStore

	EmailTemplate *template.Template

	Cfg *Config

	emailLimiter *emailRateLimiter
}

// New constructs an Auth. rts must not be nil — refresh-token rotation is a
// load-bearing security property of v5 and a nil store would silently disable
// replay protection. Use NewMemRefreshTokenStore for single-process setups.
func New(db IAuthDb, sender ICodeSender, uc IUserCreator, ev IEmailValidator, uiv IUserIdentityVerifier, rts IRefreshTokenStore, et *template.Template, cfg *Config) *Auth {
	if rts == nil {
		panic("fsa.New: IRefreshTokenStore is required (use NewMemRefreshTokenStore for in-process)")
	}
	a := &Auth{
		Db:                db,
		Sender:            sender,
		Uc:                uc,
		Ev:                ev,
		Uiv:               uiv,
		RefreshTokenStore: rts,

		EmailTemplate: et,

		Cfg: cfg,
	}
	if cfg != nil && cfg.LoginRateLimitPerEmailPerHour > 0 {
		a.emailLimiter = newEmailRateLimiter(cfg.LoginRateLimitPerEmailPerHour, time.Hour)
	}
	return a
}

func NewWithMemDbAndDefaultTemplate(sender ICodeSender, uc IUserCreator, cfg *Config) *Auth {
	return New(NewMemDb(), sender, uc, NewEmailValidator(), NewUserIdentityVerifier(), NewMemRefreshTokenStore(), nil, cfg)
}

func (a *Auth) LoginStep1SendVerificationCode(ctx context.Context, email, returnUrl string) error {
	// Validate returnUrl
	if returnUrl == "" {
		if len(a.Cfg.ReturnUrls) > 0 {
			returnUrl = a.Cfg.ReturnUrls[0]
		} else {
			return fmt.Errorf("returnUrl required and no defaults configured")
		}
	}

	validReturnUrl := false
	for _, u := range a.Cfg.ReturnUrls {
		if u == returnUrl {
			validReturnUrl = true
			break
		}
	}
	if !validReturnUrl {
		return fmt.Errorf("invalid return url: %s", returnUrl)
	}

	validEmail := a.Ev.Validate(email)
	if !validEmail {
		return fmt.Errorf("invalid email")
	}

	if a.Cfg.UseIdentity {
		canLogin, reason, err := a.Uiv.CanLogin(email)
		if !canLogin || err != nil {
			return fmt.Errorf("user cannot login %s", reason)
		}
	}

	code, err := generateCode()
	if err != nil {
		return fmt.Errorf("generate code: %w", err)
	}
	expiresAt := time.Now().Add(a.Cfg.CodeValidityPeriod)

	err = a.Db.StoreVerificationCode(email, code, expiresAt)
	if err != nil {
		return err
	}

	// send the code with URL-encoded parameters
	link := fmt.Sprintf("%s?code=%s&email=%s", returnUrl, url.QueryEscape(code), url.QueryEscape(email))
	body := a.ParseTemplate(link, code)
	err = a.Sender.Send(email, "Login Verification Code", body)
	if err != nil {
		removalErr := a.Db.RemoveVerificationCode(email)
		if removalErr != nil {
			return fmt.Errorf("failed to send code: %w; also failed to remove verification code: %v", err, removalErr)
		}
		return fmt.Errorf("failed to send code: %w", err)
	}

	return nil
}

func (a *Auth) LoginStep2ConfirmCode(ctx context.Context, email string, code string) (bool, *TokenResponse, error) {
	dbCode, expiresAt, err := a.Db.GetVerificationCode(email)
	if err != nil {
		return false, nil, err
	}

	if code != dbCode {
		return false, nil, nil
	}
	if expiresAt.Before(time.Now()) {
		return false, nil, nil
	}

	// create user if not exists
	id, _, err := a.Uc.CreateEmailVerifiedUserIfNotExists(ctx, email)
	if err != nil {
		return false, nil, err
	}

	accessToken, err := a.mintAccessToken(ctx, id, email)
	if err != nil {
		return false, nil, err
	}

	refreshToken, jti, refreshExpiresAt, err := createRefreshToken(id, email, a.Cfg.RefreshTokenSecret, a.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		return false, nil, err
	}

	if err := a.RefreshTokenStore.MarkIssued(ctx, jti, id, refreshExpiresAt); err != nil {
		return false, nil, fmt.Errorf("record refresh token: %w", err)
	}

	return true, &TokenResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}, nil
}

func (a *Auth) RefreshToken(ctx context.Context, rt string) (*TokenResponse, error) {
	token, err := jwt.Parse(rt, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.Cfg.RefreshTokenSecret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	id, ok := claims["id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	idUUID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("refresh token missing jti")
	}
	alreadyUsed, err := a.RefreshTokenStore.MarkUsed(ctx, jti)
	if err != nil {
		return nil, fmt.Errorf("refresh-token store: %w", err)
	}
	if alreadyUsed {
		return nil, fmt.Errorf("refresh token already used")
	}

	accessToken, err := a.mintAccessToken(ctx, idUUID, email)
	if err != nil {
		return nil, err
	}

	refreshToken, newJti, refreshExpiresAt, err := createRefreshToken(idUUID, email, a.Cfg.RefreshTokenSecret, a.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		return nil, err
	}

	if err := a.RefreshTokenStore.MarkIssued(ctx, newJti, idUUID, refreshExpiresAt); err != nil {
		return nil, fmt.Errorf("record refresh token: %w", err)
	}

	return &TokenResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}, nil
}

func (a *Auth) mintAccessToken(ctx context.Context, id uuid.UUID, email string) (*Token, error) {
	claims := map[string]interface{}{
		"id":    id.String(),
		"email": email,
	}
	if a.Cfg.EnrichClaims != nil {
		extra, err := a.Cfg.EnrichClaims(ctx, id, email)
		if err != nil {
			return nil, fmt.Errorf("enrich claims: %w", err)
		}
		for k, v := range extra {
			if k == "id" || k == "email" || k == "exp" {
				continue
			}
			claims[k] = v
		}
	}
	return createToken(claims, a.Cfg.AccessTokenSecret, a.Cfg.AccessTokenValidityPeriod)
}

// generateCode returns a six-digit numeric verification code using crypto/rand.
func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func createToken(claims map[string]interface{}, secret string, validityPeriod time.Duration) (*Token, error) {
	expiresAt := time.Now().Add(validityPeriod)

	claims["exp"] = expiresAt.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))

	mySigningKey := []byte(secret)
	str, err := token.SignedString(mySigningKey)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:       str,
		TokenExpiry: expiresAt,
	}, nil
}

// createRefreshToken signs a refresh token, returning the *Token, the jti
// claim used, and the expiry timestamp.
func createRefreshToken(id uuid.UUID, email, secret string, validityPeriod time.Duration) (*Token, string, time.Time, error) {
	expiresAt := time.Now().Add(validityPeriod)
	jti := uuid.NewString()

	claims := jwt.MapClaims{
		"id":    id.String(),
		"email": email,
		"exp":   expiresAt.Unix(),
		"jti":   jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	str, err := token.SignedString([]byte(secret))
	if err != nil {
		return nil, "", time.Time{}, err
	}

	return &Token{
		Token:       str,
		TokenExpiry: expiresAt,
	}, jti, expiresAt, nil
}

func (a *Auth) ParseTemplate(link, code string) string {
	data := EmailData{
		Link:      link,
		Code:      code,
		AppName:   a.Cfg.AppName,
		Logo:      a.Cfg.Logo,
		Brand:     a.Cfg.Brand,
		BrandLink: a.Cfg.BrandLink,
	}

	r := []rune(a.Cfg.AppName)
	data.AppNameL1 = string(r[0])
	data.AppNameEnd = string(r[1:])

	tpl := a.EmailTemplate

	if a.EmailTemplate == nil {
		_, filename, _, ok := runtime.Caller(0)
		if !ok {
			panic("No caller information")
		}
		templatePath := filepath.Join(filepath.Dir(filename), "email_template.gohtml")
		var err error
		tpl, err = template.ParseFiles(templatePath)
		if err != nil {
			panic(err)
		}
	}

	var body bytes.Buffer
	err := tpl.ExecuteTemplate(&body, "email", data)
	if err != nil {
		panic(err)
	}

	return body.String()
}

// resolvedPrefix returns the configured auth route prefix, defaulting to
// /auth. The configured value is normalized so callers can pass "auth",
// "/auth/", or "auth/" interchangeably; an effectively empty prefix
// (e.g. "/" or "") falls back to the default.
func (c *Config) resolvedPrefix() string {
	if c == nil {
		return "/auth"
	}
	p := strings.TrimRight(c.Prefix, "/")
	if p == "" {
		return "/auth"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
