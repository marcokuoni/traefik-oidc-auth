package src

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/errorPages"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func newBackend401ModeTest(t *testing.T, next http.Handler, discovery *oidc.OidcDiscovery, client *http.Client) *TraefikOidcAuth {
	t.Helper()

	callbackURL, err := url.Parse("/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}

	return &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		next:   next,
		Config: &Config{
			Secret:                   "12345678901234567890123456789012",
			Scopes:                   []string{"openid"},
			LogoutUri:                "/logout",
			CallbackUri:              "/oidc/callback",
			UnauthorizedBehavior:     "Challenge",
			AuthenticateOnBackend401: true,
			Provider:                 &ProviderConfig{ClientId: "test", TokenValidation: "Introspection"},
			Authorization:            &AuthorizationConfig{},
			SessionCookie:            &SessionCookieConfig{Path: "/", Secure: false, HttpOnly: true, SameSite: "default"},
			AuthorizationHeader:      &AuthorizationHeaderConfig{Name: "Authorization"},
			AuthorizationCookie:      &AuthorizationCookieConfig{},
			ErrorPages: &errorPages.ErrorPagesConfig{
				Unauthenticated: &errorPages.ErrorPageConfig{},
				Unauthorized:    &errorPages.ErrorPageConfig{},
			},
		},
		CallbackURL:       callbackURL,
		httpClient:        client,
		DiscoveryDocument: discovery,
		SessionStorage:    session.CreateCookieSessionStorage(),
	}
}

func TestServeHTTP_AuthenticateOnBackend401_NoSessionTriggersAuth(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
	})

	toa := newBackend401ModeTest(t, next, &oidc.OidcDiscovery{AuthorizationEndpoint: "https://idp.example.com/authorize"}, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	toa.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatalf("expected redirect location")
	}
}

func TestServeHTTP_AuthenticateOnBackend401_WithSessionReturnsBackend401(t *testing.T) {
	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": true, "sub": "abc"})
	}))
	defer introspectionServer.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("backend unauthorized"))
	})

	toa := newBackend401ModeTest(
		t,
		next,
		&oidc.OidcDiscovery{AuthorizationEndpoint: "https://idp.example.com/authorize", IntrospectionEndpoint: introspectionServer.URL},
		introspectionServer.Client(),
	)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()

	toa.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	if rr.Body.String() != "backend unauthorized" {
		t.Fatalf("expected backend body, got %q", rr.Body.String())
	}
}
