package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var (
	oidcConfig   *oidc.Config
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	pkceVerifier string
)

func main() {
	router := gin.Default()

	// Load the HTML template
	router.LoadHTMLGlob("templates/*")

	// Landing page
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "OIDC Test Client",
		})
	})

	// Start OIDC flow
	router.POST("/start", startOIDCFlow)

	// Handle OIDC callback
	router.GET("/callback", handleOIDCCallback)

	// Run the server
	router.Run(":8080")
}

func startOIDCFlow(c *gin.Context) {
	var req struct {
		ClientID     string `form:"client_id"`
		ClientSecret string `form:"client_secret"`
		Issuer       string `form:"issuer"`
		RedirectURI  string `form:"redirect_uri"`
		Scopes       string `form:"scopes"`
		PKCE         string `form:"pkce"`
	}

	if err := c.ShouldBind(&req); err != nil {
		c.String(http.StatusBadRequest, "Invalid request")
		return
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, req.Issuer)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to fetch OIDC provider: %v", err)
		return
	}

	oidcConfig = &oidc.Config{ClientID: req.ClientID}
	verifier = provider.Verifier(oidcConfig)

	oauth2Config = oauth2.Config{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  req.RedirectURI,
		Scopes:       []string{oidc.ScopeOpenID, req.Scopes},
	}

	state, err := generateRandomString(16)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to generate state")
		return
	}

	c.SetCookie("oidc_state", state, 3600, "/", "localhost", false, true)

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if req.PKCE == "true" {
		pkceVerifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pkceVerifier))
	}

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
		// If there's an error, display a user-friendly error message
		errorDescription := c.Query("error_description")
		if errorDescription == "" {
			errorDescription = "An unknown error occurred."
		}

		// Prepare data for the error template
		type ErrorPageData struct {
			Error       string
			Description string
		}

		data := ErrorPageData{
			Error:       erro,
			Description: errorDescription,
		}

		// Render the error template
		c.HTML(http.StatusBadRequest, "error.html", data)
		return
	}

	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Authorization code not found")
		return
	}

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
	c.HTML(http.StatusOK, "callback.html", gin.H{
		"AccessToken": token.AccessToken,
		"IDToken":     rawIDToken,
		"Claims":      claims,
	})
}
