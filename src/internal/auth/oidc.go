package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"go.uber.org/zap"

	"oidc-code-server-wrapper/internal/config"
)

type OIDCAuth struct {
	config   *config.Config
	logger   *zap.SugaredLogger
	provider *oidc.Provider
	oauth2   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

type UserInfo struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	Username      string `json:"preferred_username"`
}

func NewOIDCAuth(cfg *config.Config, logger *zap.SugaredLogger) *OIDCAuth {
	ctx := context.Background()

	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, cfg.OIDC.ProviderURL)
	if err != nil {
		logger.Fatalf("Failed to create OIDC provider: %v", err)
	}

	// Configure OAuth2
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL:  cfg.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.OIDC.ClientID,
	})

	logger.Info("OIDC provider configured successfully",
		zap.String("issuer", cfg.OIDC.ProviderURL),
		zap.String("client_id", cfg.OIDC.ClientID))

	return &OIDCAuth{
		config:   cfg,
		logger:   logger,
		provider: provider,
		oauth2:   oauth2Config,
		verifier: verifier,
	}
}

// GenerateRandomString generates a random string for state/nonce
func (a *OIDCAuth) GenerateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GetAuthURL generates the authorization URL for the OIDC flow
func (a *OIDCAuth) GetAuthURL(state string) string {
	return a.oauth2.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)
}

// ExchangeCode exchanges the authorization code for tokens
func (a *OIDCAuth) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return a.oauth2.Exchange(ctx, code)
}

// VerifyIDToken verifies and parses the ID token
func (a *OIDCAuth) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return a.verifier.Verify(ctx, rawIDToken)
}

// GetUserInfo extracts user information from the ID token and userinfo endpoint
func (a *OIDCAuth) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	// First, try to get claims from ID token
	var userInfo UserInfo
	
	if idToken, ok := token.Extra("id_token").(string); ok && idToken != "" {
		parsedToken, err := a.VerifyIDToken(ctx, idToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify ID token: %w", err)
		}
		
		if err := parsedToken.Claims(&userInfo); err != nil {
			return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
		}
	}
	
	// If email is not in ID token, try userinfo endpoint
	if userInfo.Email == "" {
		client := a.oauth2.Client(ctx, token)
		resp, err := client.Get(a.provider.Endpoint().AuthURL + "/userinfo")
		if err != nil {
			return nil, fmt.Errorf("failed to get userinfo: %w", err)
		}
		defer resp.Body.Close()
		
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			return nil, fmt.Errorf("failed to decode userinfo: %w", err)
		}
	}
	
	// Ensure email is verified
	if !userInfo.EmailVerified {
		a.logger.Warn("User email not verified", zap.String("email", userInfo.Email))
	}
	
	return &userInfo, nil
}

// GetUsernameFromEmail extracts username from email address
func (a *OIDCAuth) GetUsernameFromEmail(email string) string {
	// Extract username from email (before @)
	for i, c := range email {
		if c == '@' {
			return email[:i]
		}
	}
	return email
}

// GetUsername determines the username from user info, preferring OIDC username claim
func (a *OIDCAuth) GetUsername(userInfo *UserInfo) string {
	// First, try to use the preferred_username from OIDC claims
	if userInfo.Username != "" {
		return userInfo.Username
	}
	
	// Fallback to extracting from email
	return a.GetUsernameFromEmail(userInfo.Email)
}

// RefreshToken refreshes the access token using the refresh token
func (a *OIDCAuth) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	
	return a.oauth2.TokenSource(ctx, token).Token()
}