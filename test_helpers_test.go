package fsa

import (
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type MockSender struct {
	LastTo      string
	LastSubject string
	LastBody    string
}

func (m *MockSender) Send(to, subject, body string) error {
	m.LastTo = to
	m.LastSubject = subject
	m.LastBody = body
	return nil
}

type MockUserCreator struct{}

func (m *MockUserCreator) CreateEmailVerifiedUserIfNotExists(ctx context.Context, email string) (uuid.UUID, bool, error) {
	return uuid.New(), true, nil
}

func createTestAuth() *Auth {
	return createTestAuthWithConfig(&Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "test-access-secret",
		RefreshTokenSecret:         "test-refresh-secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	})
}

func createTestAuthWithConfig(cfg *Config) *Auth {
	return New(NewMemDb(), &MockSender{}, &MockUserCreator{}, NewEmailValidator(), nil, nil, cfg)
}

func createTestAuthWithMockSender(sender *MockSender) *Auth {
	return New(NewMemDb(), sender, &MockUserCreator{}, NewEmailValidator(), nil, nil, &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://app.com/login"},
		AccessTokenSecret:          "test-access-secret",
		RefreshTokenSecret:         "test-refresh-secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	})
}

func createValidToken(secret, email, userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"id":    userID,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	str, _ := token.SignedString([]byte(secret))
	return str
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
