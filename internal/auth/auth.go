package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey struct{}

// Claims represents the authenticated user's identity and group memberships.
type Claims struct {
	Subject string
	Groups  []string
}

// FromContext retrieves the authenticated Claims from the request context.
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKey{}).(*Claims)
	return c
}

// Config holds OIDC validation settings.
type Config struct {
	IssuerURL string
	ClientID  string
}

// JWTMiddleware validates Bearer tokens as JWTs against the issuer's JWKS.
func JWTMiddleware(cfg Config, jwks keyfunc.Keyfunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractBearer(r)
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenStr, jwks.KeyfuncCtx(r.Context()),
			jwt.WithIssuer(cfg.IssuerURL),
			jwt.WithAudience(cfg.ClientID),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !token.Valid {
			http.Error(w, fmt.Sprintf("invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		claims, err := extractClaims(token)
		if err != nil {
			http.Error(w, "invalid claims", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// StubMiddleware is a no-validation middleware for development. Trusts Bearer value as subject.
func StubMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		groups := parseGroups(r.Header.Get("X-Groups"))
		claims := &Claims{Subject: token, Groups: groups}
		ctx := context.WithValue(r.Context(), ctxKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return ""
	}
	return token
}

func extractClaims(token *jwt.Token) (*Claims, error) {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	sub, _ := mapClaims.GetSubject()
	groups := extractGroups(mapClaims)

	return &Claims{Subject: sub, Groups: groups}, nil
}

func extractGroups(claims jwt.MapClaims) []string {
	// Try "groups" claim (Dex, Keycloak)
	raw, ok := claims["groups"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	groups := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups
}

func parseGroups(header string) []string {
	if header == "" {
		return nil
	}
	var groups []string
	for _, g := range strings.Split(header, ",") {
		if s := strings.TrimSpace(g); s != "" {
			groups = append(groups, s)
		}
	}
	return groups
}
