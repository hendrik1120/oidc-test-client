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
	returnedState := c.Query("state")
	stateCookie, err := c.Cookie("oidc_state")
	if err != nil || returnedState != stateCookie {
		c.String(http.StatusBadRequest, "Invalid state")
		return
	}

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

	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Authorization code not found")
		return
	}

	pkceVerifier, err := c.Cookie("oidc_pkce")
	ctx := context.Background()
	opts := []oauth2.AuthCodeOption{}
	if pkceVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(pkceVerifier))
	}

	token, err := oauth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token: %v", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.String(http.StatusInternalServerError, "No ID token found")
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to verify ID token: %v", err)
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		c.String(http.StatusInternalServerError, "Failed to parse claims: %v", err)
		return
	}

	// Render the HTML template with the tokens and claims
	c.HTML(http.StatusOK, "callback.tmpl", gin.H{
		"AccessToken": token.AccessToken,
		"IDToken":     rawIDToken,
		"Claims":      claims,
	})
}
