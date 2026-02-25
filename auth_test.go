package fsa

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Phase 1: URL Encoding Tests

func TestLoginStep1_URLEncodesEmailWithPlusSign(t *testing.T) {
	mockSender := &MockSender{}
	auth := createTestAuthWithMockSender(mockSender)

	err := auth.LoginStep1SendVerificationCode(context.Background(), "test+user@example.com", "https://app.com/login")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(mockSender.LastBody, "email=test%2Buser%40example.com") {
		t.Errorf("expected URL-encoded email with plus sign, got body: %s", mockSender.LastBody)
	}
	if strings.Contains(mockSender.LastBody, "email=test+user@") {
		t.Error("email should be URL-encoded, not raw")
	}
}

func TestLoginStep1_URLEncodesEmailWithAmpersand(t *testing.T) {
	mockSender := &MockSender{}
	auth := createTestAuthWithMockSender(mockSender)

	err := auth.LoginStep1SendVerificationCode(context.Background(), "test&user@example.com", "https://app.com/login")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(mockSender.LastBody, "email=test%26user%40example.com") {
		t.Errorf("expected URL-encoded email with ampersand, got body: %s", mockSender.LastBody)
	}
}

func TestLoginStep1_URLEncodesSpecialCharacters(t *testing.T) {
	testCases := []struct {
		email    string
		expected string
	}{
		{"test+user@example.com", "test%2Buser%40example.com"},
		{"test&user@example.com", "test%26user%40example.com"},
		{"test=user@example.com", "test%3Duser%40example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.email, func(t *testing.T) {
			mockSender := &MockSender{}
			auth := createTestAuthWithMockSender(mockSender)

			err := auth.LoginStep1SendVerificationCode(context.Background(), tc.email, "https://app.com/login")

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(mockSender.LastBody, "email="+tc.expected) {
				t.Errorf("expected email=%s in body, got: %s", tc.expected, mockSender.LastBody)
			}
		})
	}
}

// Phase 1: Input Validation Tests

func TestLoginStep1_DefaultsEmptyReturnUrl(t *testing.T) {
	mockSender := &MockSender{}
	auth := New(NewMemDb(), mockSender, &MockUserCreator{}, NewEmailValidator(), nil, nil, &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://default.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	})

	err := auth.LoginStep1SendVerificationCode(context.Background(), "test@example.com", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(mockSender.LastBody, "https://default.com/login") {
		t.Errorf("expected default return URL in body, got: %s", mockSender.LastBody)
	}
}

func TestLoginStep1_RejectsInvalidReturnUrl(t *testing.T) {
	mockSender := &MockSender{}
	auth := New(NewMemDb(), mockSender, &MockUserCreator{}, NewEmailValidator(), nil, nil, &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://allowed.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	})

	err := auth.LoginStep1SendVerificationCode(context.Background(), "test@example.com", "https://evil.com/login")

	if err == nil {
		t.Fatal("expected error for invalid return URL")
	}
	if !strings.Contains(err.Error(), "invalid return url") {
		t.Errorf("expected 'invalid return url' error, got: %v", err)
	}
	if mockSender.LastBody != "" {
		t.Error("email should not be sent for invalid return URL")
	}
}

func TestLoginStep1_ErrorsWhenNoReturnUrlsConfigured(t *testing.T) {
	mockSender := &MockSender{}
	auth := New(NewMemDb(), mockSender, &MockUserCreator{}, NewEmailValidator(), nil, nil, &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	})

	err := auth.LoginStep1SendVerificationCode(context.Background(), "test@example.com", "")

	if err == nil {
		t.Fatal("expected error when no return URLs configured")
	}
	if !strings.Contains(err.Error(), "no defaults configured") {
		t.Errorf("expected 'no defaults configured' error, got: %v", err)
	}
}

func TestLoginStep2_RejectsWrongCode(t *testing.T) {
	auth := createTestAuth()
	email := "test@example.com"
	err := auth.Db.StoreVerificationCode(email, "123456", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("failed to store code: %v", err)
	}

	confirmed, tokens, err := auth.LoginStep2ConfirmCode(context.Background(), email, "000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if confirmed {
		t.Error("expected confirmed to be false for wrong code")
	}
	if tokens != nil {
		t.Error("expected tokens to be nil for wrong code")
	}
}

func TestLoginStep2_RejectsExpiredCode(t *testing.T) {
	auth := createTestAuth()
	email := "test@example.com"
	err := auth.Db.StoreVerificationCode(email, "123456", time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("failed to store code: %v", err)
	}

	confirmed, tokens, err := auth.LoginStep2ConfirmCode(context.Background(), email, "123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if confirmed {
		t.Error("expected confirmed to be false for expired code")
	}
	if tokens != nil {
		t.Error("expected tokens to be nil for expired code")
	}
}

func TestRefreshToken_RejectsExpiredJWT(t *testing.T) {
	auth := createTestAuth()

	// Create an expired refresh token
	expiredToken, err := createRefreshToken(
		uuid.New(),
		"test@example.com",
		auth.Cfg.RefreshTokenSecret,
		-1*time.Hour, // already expired
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	_, err = auth.RefreshToken(context.Background(), expiredToken.Token)
	if err == nil {
		t.Error("expected error for expired JWT")
	}
}

func TestRefreshToken_RejectsInvalidJWT(t *testing.T) {
	auth := createTestAuth()

	_, err := auth.RefreshToken(context.Background(), "not-a-valid-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestRefreshToken_ReturnsNewTokenPair(t *testing.T) {
	auth := createTestAuth()

	refreshToken, err := createRefreshToken(
		uuid.New(),
		"test@example.com",
		auth.Cfg.RefreshTokenSecret,
		auth.Cfg.RefreshTokenValidityPeriod,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	tokens, err := auth.RefreshToken(context.Background(), refreshToken.Token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens == nil {
		t.Fatal("expected non-nil token response")
	}
	if tokens.AccessToken == nil || tokens.AccessToken.Token == "" {
		t.Error("expected non-empty access token")
	}
	if tokens.RefreshToken == nil || tokens.RefreshToken.Token == "" {
		t.Error("expected non-empty refresh token")
	}
}

func TestLoginStep1_AcceptsValidReturnUrl(t *testing.T) {
	mockSender := &MockSender{}
	auth := New(NewMemDb(), mockSender, &MockUserCreator{}, NewEmailValidator(), nil, nil, &Config{
		AppName:                    "TestApp",
		ReturnUrls:                 []string{"https://app1.com/login", "https://app2.com/login"},
		AccessTokenSecret:          "secret",
		RefreshTokenSecret:         "secret",
		CodeValidityPeriod:         5 * time.Minute,
		AccessTokenValidityPeriod:  1 * time.Hour,
		RefreshTokenValidityPeriod: 24 * time.Hour,
	})

	// Test first allowed URL
	err := auth.LoginStep1SendVerificationCode(context.Background(), "test@example.com", "https://app1.com/login")
	if err != nil {
		t.Fatalf("unexpected error for first allowed URL: %v", err)
	}

	// Test second allowed URL
	err = auth.LoginStep1SendVerificationCode(context.Background(), "test2@example.com", "https://app2.com/login")
	if err != nil {
		t.Fatalf("unexpected error for second allowed URL: %v", err)
	}
}
