# FSA

F***ing Simple Auth. A simple authentication library for Go.

Send email verification codes. Get JWT tokens.

## Usage

- Create a new instance of the authenticator
  - `New()` takes in a Config (defined in auth.go), an `IAuthDb`, an `ICodeSender`, an `IUserCreator`, an `IEmailValidator`, an `IUserIdentityVerifier`, an `IRefreshTokenStore`, and an optional `*html/template.Template`.
  - `NewWithMemDbAndDefaultTemplate()` takes a Config, an `ICodeSender`, and an `IUserCreator`, and wires sensible in-memory defaults for everything else.
- The chi middleware can be wired up with the Config (call `NewChiMiddleware`) to verify JWTs from either the `Authorization` header or the `access_token` cookie.
- `LoginStep1SendVerificationCode` sends a verification code to the passed email address.
- `LoginStep2ConfirmCode` validates the code, creates the user if needed, and returns a token pair.
- Verification codes are generated with `crypto/rand`.
- Refresh tokens are rotated on use: each refresh mints a new `jti` and the previous one is rejected on replay (see [IRefreshTokenStore](#irefreshtokenstore)).
- Access token claims can be enriched via the `EnrichClaims` hook on Config (see [Custom claims](#custom-claims)). Base claims (`id`, `email`, `exp`) cannot be overwritten.

## Config highlights

- `Prefix` — route prefix for the bundled handlers. Default `/auth`. Set e.g. `/api/v1/auth` to mount alongside other versioned routes. `CookieConfig.RefreshPath` defaults to `Prefix + "/refresh"`.
- `RateLimitPerSecond` — per-IP rate limit on the bundled routes. `0` disables it.
- `LoginRateLimitPerEmailPerHour` — per-email sliding-window rate limit on `/login` and `/confirm`. Complements the per-IP limiter to prevent inbox flooding and cross-IP enumeration. `0` disables it.
- `CORSConfig` — when non-nil, installs a CORS middleware on the bundled routes (and registers OPTIONS preflight handlers).
- `EnrichClaims` — hook for adding custom claims to access tokens.

## IAuthDb
Storage for verification codes. The in-memory implementation from `NewMemDb()` is fine for single-process tests; production deployments should plug in their own.

## IUserCreator
Creates a user in your system if they don't already exist.

## ICodeSender
Sends the verification code to the user (SMTP, SES, Postmark, etc.).

## IEmailValidator
Validates the email address provided. The default implementation uses `net/mail`.

## IRefreshTokenStore
Tracks refresh tokens by their `jti` claim and rejects replay. `NewMemRefreshTokenStore()` provides an in-memory implementation; production deployments typically back this with Redis-with-TTL or a database table.

## Custom claims
Set `Config.EnrichClaims` to attach project- or tenant-specific claims to access tokens. The hook receives the user ID and email and returns a map that is merged into the base claims. `id`, `email`, and `exp` cannot be overridden.

```go
cfg.EnrichClaims = func(ctx context.Context, id uuid.UUID, email string) (map[string]any, error) {
    return map[string]any{"role": "admin", "org": "acme"}, nil
}
```

## Todo

- [ ] Add a simple sender implementation for SMTP (Mailhog is a good option for testing)
- [ ] Optional `RevokeAllForUser` on `IRefreshTokenStore` so replay detection can invalidate the entire chain
