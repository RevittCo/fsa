package fsa

import (
	"context"
	"html"
	"html/template"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

type loginLinkDB struct {
	email, code string
	stores      int
}

func (d *loginLinkDB) StoreVerificationCode(email, code string, _ time.Time) error {
	d.email, d.code = email, code
	d.stores++
	return nil
}

func (d *loginLinkDB) GetVerificationCode(string) (string, time.Time, error) {
	return d.code, time.Now().Add(time.Minute), nil
}

func (d *loginLinkDB) RemoveVerificationCode(string) error { return nil }

type loginLinkSender struct {
	to, body string
	sends    int
}

func (s *loginLinkSender) Send(to, _ string, body string) error {
	s.to, s.body = to, body
	s.sends++
	return nil
}

func newLoginLinkAuth(db *loginLinkDB, sender *loginLinkSender, tpl *template.Template, returnURL string) *Auth {
	return New(db, sender, nil, NewEmailValidator(), nil, NewMemRefreshTokenStore(), tpl, &Config{
		AppName: "FSA Test", ReturnUrls: []string{returnURL}, CodeValidityPeriod: time.Minute,
	})
}

func TestLoginStep1RenderedLinkRoundTrips(t *testing.T) {
	custom := template.Must(template.New("email").Parse(`{{define "email"}}<a href="{{.Link}}">Login</a><p>{{.Code}}</p>{{end}}`))
	for _, templateCase := range []struct {
		name string
		tpl  *template.Template
	}{
		{name: "default"},
		{name: "custom", tpl: custom},
	} {
		t.Run(templateCase.name, func(t *testing.T) {
			for _, tt := range []struct {
				name, email, returnURL string
			}{
				{name: "plain", email: "user@example.com", returnURL: "https://app.example/login"},
				{name: "plus", email: "user+alias@example.com", returnURL: "https://app.example/login"},
				{name: "ampersand", email: "user&alias@example.com", returnURL: "https://app.example/login"},
				{name: "percent", email: "user%alias@example.com", returnURL: "https://app.example/login"},
				{name: "literal percent escape", email: "user%2Balias@example.com", returnURL: "https://app.example/login"},
				{name: "query and fragment", email: "user+one&two%three@example.com", returnURL: "https://app.example/login?next=%2Forders%3Fstate%3Dopen%26page%3D2&source=email&source=login#account%20panel"},
				{name: "replace stale auth values", email: "user+alias@example.com", returnURL: "https://app.example/login?code=old&code=older&email=other%40example.com&next=%2Forders#login"},
				{name: "fragment only", email: "user+alias@example.com", returnURL: "https://app.example/login#account%20panel"},
				{name: "relative return URL", email: "user+alias@example.com", returnURL: "/login?source=email#account"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					db, sender := &loginLinkDB{}, &loginLinkSender{}
					auth := newLoginLinkAuth(db, sender, templateCase.tpl, tt.returnURL)
					if err := auth.LoginStep1SendVerificationCode(context.Background(), tt.email, tt.returnURL); err != nil {
						t.Fatal(err)
					}
					if sender.sends != 1 || sender.to != tt.email || db.stores != 1 || db.email != tt.email || len(db.code) != 6 {
						t.Fatalf("receipt/challenge mismatch: sender=%+v db=%+v", sender, db)
					}
					matches := regexp.MustCompile(`href="([^"]*)"`).FindStringSubmatch(sender.body)
					if len(matches) != 2 {
						t.Fatalf("rendered login href missing: %s", sender.body)
					}
					// An email client decodes HTML entities before navigating the href.
					href, err := url.Parse(html.UnescapeString(matches[1]))
					if err != nil {
						t.Fatal(err)
					}
					values, err := url.ParseQuery(href.RawQuery)
					if err != nil {
						t.Fatal(err)
					}
					original, err := url.Parse(tt.returnURL)
					if err != nil {
						t.Fatal(err)
					}
					want := original.Query()
					want.Set("email", tt.email)
					want.Set("code", db.code)
					if !reflect.DeepEqual(values, want) {
						t.Fatalf("decoded query=%v, want %v; href=%s", values, want, href)
					}
					if href.Scheme != original.Scheme || href.Host != original.Host || href.EscapedPath() != original.EscapedPath() || href.EscapedFragment() != original.EscapedFragment() {
						t.Fatalf("return URL path/origin/fragment changed: %s", href)
					}
					if !strings.Contains(sender.body, db.code) {
						t.Fatal("verification code missing from rendered email")
					}
				})
			}
		})
	}
}

func TestLoginStep1RejectsMalformedReturnURLBeforeStore(t *testing.T) {
	for _, returnURL := range []string{"https://app.example/%zz", "https://app.example/login?next=%zz", "https://app.example/login?next=a;b"} {
		t.Run(returnURL, func(t *testing.T) {
			db, sender := &loginLinkDB{}, &loginLinkSender{}
			auth := newLoginLinkAuth(db, sender, nil, returnURL)
			if err := auth.LoginStep1SendVerificationCode(context.Background(), "user@example.com", returnURL); err == nil {
				t.Fatal("malformed URL must fail before retaining a challenge or sending email")
			}
			if db.stores != 0 || sender.sends != 0 {
				t.Fatalf("side effects after invalid URL: stores=%d sends=%d", db.stores, sender.sends)
			}
		})
	}
}
