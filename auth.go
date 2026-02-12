package fsa

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

type Key string

const ClaimsKey Key = "claims"
const UserEmailKey Key = "userEmail"
const UserIdKey Key = "userId"

type CookieConfig struct {
	Domain   string        // For cross-subdomain auth
	Secure   bool          // HTTPS only (default: true)
	SameSite http.SameSite // Default: SameSiteStrictMode
}

type CSRFConfig struct {
	CookieName  string // Default: "csrf_token"
	HeaderName  string // Default: "X-CSRF-Token"
	TokenLength int    // Default: 32
}

type Config struct {
	AppName   string
	Logo      string
	Brand     string
	BrandLink string

	CodeValidityPeriod         time.Duration
	AccessTokenValidityPeriod  time.Duration
	RefreshTokenValidityPeriod time.Duration

	AccessTokenSecret  string
	RefreshTokenSecret string

	RateLimitPerSecond int

	ReturnUrls []string

	UseIdentity bool

	CookieConfig *CookieConfig // Optional, uses secure defaults if nil
	CSRFConfig   *CSRFConfig   // Optional, uses defaults if nil
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
	Db     IAuthDb
	Sender ICodeSender
	Uc     IUserCreator
	Ev     IEmailValidator
	Uiv    IUserIdentityVerifier

	EmailTemplate *template.Template

	Cfg *Config
}

func New(db IAuthDb, sender ICodeSender, uc IUserCreator, ev IEmailValidator, uiv IUserIdentityVerifier, et *template.Template, cfg *Config) *Auth {
	return &Auth{
		Db:     db,
		Sender: sender,
		Uc:     uc,
		Ev:     ev,
		Uiv:    uiv,

		EmailTemplate: et,

		Cfg: cfg,
	}
}

func NewWithMemDbAndDefaultTemplate(sender ICodeSender, uc IUserCreator, cfg *Config) *Auth {
	return New(NewMemDb(), sender, uc, NewEmailValidator(), NewUserIdentityVerifier(), nil, cfg)
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

	code := generateCode()
	expiresAt := time.Now().Add(a.Cfg.CodeValidityPeriod)

	err := a.Db.StoreVerificationCode(email, code, expiresAt)
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

	accessToken, err := createToken(map[string]interface{}{
		"id":    id,
		"email": email,
	}, a.Cfg.AccessTokenSecret, a.Cfg.AccessTokenValidityPeriod)
	if err != nil {
		return false, nil, err
	}

	refreshToken, err := createRefreshToken(id, email, a.Cfg.RefreshTokenSecret, a.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		return false, nil, err
	}

	return true, &TokenResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}, nil
}

func (a *Auth) RefreshToken(ctx context.Context, rt string) (*TokenResponse, error) {
	token, err := jwt.Parse(rt, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.Cfg.RefreshTokenSecret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
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

	accessToken, err := createToken(map[string]interface{}{
		"id":    id,
		"email": email,
	}, a.Cfg.AccessTokenSecret, a.Cfg.AccessTokenValidityPeriod)
	if err != nil {
		return nil, err
	}

	refreshToken, err := createRefreshToken(idUUID, email, a.Cfg.RefreshTokenSecret, a.Cfg.RefreshTokenValidityPeriod)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}, nil
}

func generateCode() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	var code string
	for i := 0; i < 6; i++ {
		code += strconv.Itoa(r.Intn(10))
	}
	return code
}

func createToken(claims map[string]interface{}, secret string, validityPeriod time.Duration) (*Token, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	expiresAt := time.Now().Add(validityPeriod)

	claims["exp"] = expiresAt.Unix()
	token.Claims = jwt.MapClaims(claims)

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

func createRefreshToken(id uuid.UUID, email, secret string, validityPeriod time.Duration) (*Token, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	expiresAt := time.Now().Add(validityPeriod)

	claims := jwt.MapClaims{
		"id":    id.String(),
		"email": email,
		"exp":   expiresAt.Unix(),
	}
	token.Claims = claims

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
