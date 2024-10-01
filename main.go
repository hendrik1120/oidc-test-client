package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)

// Generates a random string of a specified length.
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Extracts the domain from a given URL string
func extractDomain(inputURL string) (string, error) {
	// Parse the URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}
	// Return the host (domain) part of the URL
	return parsedURL.Hostname(), nil
}

var (
	oidcConfig   *oidc.Config
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
)

var req = struct {
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	Issuer       string `form:"issuer"`
	RedirectURI  string `form:"redirect_uri"`
	Scopes       string `form:"scopes"`
}{
	Issuer:      "https://auth.example.com",
	RedirectURI: "http://localhost:8080/callback",
	Scopes:      "openid email profile",
}

func main() {
	router := gin.Default()

	// Load the HTML template
	router.LoadHTMLGlob("templates/*")

	// Landing page
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title": "OIDC Test Client",
			"req":   req,
		})
	})

	// Start OIDC flow
	router.POST("/start", startOIDCFlow)

	// Handle OIDC callback
	router.GET("/callback", handleOIDCCallback)

	// Run the server
	router.Run(":8080")
}

// OIDC + OAUTH2 flow
func startOIDCFlow(c *gin.Context) {
	// Read template
	if err := c.ShouldBind(&req); err != nil {
		c.String(http.StatusBadRequest, "Invalid request")
		return
	}

	// extract the domain from the callback url to store cookies
	domain, _ := extractDomain(req.RedirectURI)

	// Query OIDC discovery endpoint
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, req.Issuer)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to fetch OIDC provider: %v", err)
		return
	}

	// Generate JWT verifier and configure OAUTH2 from discovery endpoint
	oidcConfig = &oidc.Config{ClientID: req.ClientID}
	verifier = provider.Verifier(oidcConfig)

	oauth2Config = oauth2.Config{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  req.RedirectURI,
		Scopes:       []string{oidc.ScopeOpenID, req.Scopes},
	}

	// Generate and set state cookie
	state, err := generateRandomString(16)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to generate state")
		return
	}
	c.SetCookie("oidc_state", state, 300, "/", domain, false, true)

	// Always include PKCE challenge
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	pkceVerifier := oauth2.GenerateVerifier()
	opts = append(opts, oauth2.S256ChallengeOption(pkceVerifier))
	c.SetCookie("oidc_pkce", pkceVerifier, 300, "/", domain, false, true)

	// Generate auth url and redirect
	authCodeURL := oauth2Config.AuthCodeURL(state, opts...)
	c.Redirect(http.StatusFound, authCodeURL)
}

func handleOIDCCallback(c *gin.Context) {
	// Check provider and client state matches
	returnedState := c.Query("state")
	stateCookie, err := c.Cookie("oidc_state")
	if err != nil || returnedState != stateCookie {
		c.String(http.StatusBadRequest, "Invalid state")
		return
	}

	// Display errors from provider
	erro := c.Query("error")
	if erro != "" {
		errorDescription := c.Query("error_description")
		if errorDescription == "" {
			errorDescription = "An unknown error occurred."
		}

		type ErrorPageData struct {
			Error       string
			Description string
		}

		data := ErrorPageData{
			Error:       erro,
			Description: errorDescription,
		}

		c.HTML(http.StatusBadRequest, "error.tmpl", data)
		return
	}

	// Check if the response include an authz code
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Authorization code not found")
		return
	}

	// Include pkce verifier in exchange
	pkceVerifier, err := c.Cookie("oidc_pkce")
	ctx := context.Background()
	opts := []oauth2.AuthCodeOption{}
	if pkceVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(pkceVerifier))
	}

	// Exchange authz code for ID Token
	token, err := oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token: %v", err)
		return
	}

	// Extract raw token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.String(http.StatusInternalServerError, "No ID token found")
		return
	}

	// Verify raw token
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to verify ID token: %v", err)
		return
	}

	// Parse claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		c.String(http.StatusInternalServerError, "Failed to parse claims: %v", err)
		return
	}

	// Replace timestamps with formatted date time objects
	if authTime, ok := claims["auth_time"].(float64); ok {
		claims["auth_time"] = time.Unix(int64(authTime), 0).Format(time.RFC1123)
	}

	if exp, ok := claims["exp"].(float64); ok {
		claims["exp"] = time.Unix(int64(exp), 0).Format(time.RFC1123)
	}

	if iat, ok := claims["iat"].(float64); ok {
		claims["iat"] = time.Unix(int64(iat), 0).Format(time.RFC1123)
	}

	// Render the HTML template with the tokens and claims
	c.HTML(http.StatusOK, "callback.tmpl", gin.H{
		"AccessToken": token.AccessToken,
		"IDToken":     rawIDToken,
		"Claims":      claims,
	})
}
