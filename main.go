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

// Formats specified claims to RFC1123 format
func formatTimestampClaims(tokenClaims map[string]interface{}, claimKeys ...string) {
	for _, claimKey := range claimKeys {
		if timestamp, ok := tokenClaims[claimKey].(float64); ok {
			tokenClaims[claimKey] = time.Unix(int64(timestamp), 0).Format(time.RFC1123)
		}
	}
}

var (
	oauth2Config oauth2.Config
	oidcProvider *oidc.Provider
	jwtVerifier  *oidc.IDTokenVerifier
	authCodeURL  string
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
	domain, err := extractDomain(req.RedirectURI)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to extract domain from callback: %v", err)
		return
	}

	// Query OIDC discovery endpoint
	ctx := context.Background()
	oidcProvider, err = oidc.NewProvider(ctx, req.Issuer)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to fetch OIDC provider: %v", err)
		return
	}

	// Get endpoints and generate JWT verifier
	oidcConfig := &oidc.Config{ClientID: req.ClientID}
	endpoint := oidcProvider.Endpoint()
	jwtVerifier = oidcProvider.Verifier(oidcConfig)

	// Configuring oauth2 with the endpoints available from the oidc lib. Using authelia defaults for the rest.
	oauth2Config = oauth2.Config{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  endpoint.AuthURL,
			TokenURL: endpoint.TokenURL,
			//PushedAuthURL:    domain + "/api/oidc/pushed-authorization-request",
			//IntrospectionURL: domain + "/api/oidc/introspection",
			//RevocationURL:    domain + "/api/oidc/revocation",
			//UserinfoURL:      domain + "/api/oidc/userinfo",
			//JWKSURL:          domain + "/jwks.json",
			DeviceAuthURL: endpoint.DeviceAuthURL,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
		RedirectURL: req.RedirectURI,
		Scopes:      []string{req.Scopes},
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
	authCodeURL = oauth2Config.AuthCodeURL(state, opts...)
	c.Redirect(http.StatusFound, authCodeURL)
}

func handleOIDCCallback(c *gin.Context) {
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

	var (
		token        *oauth2.Token
		idToken      *oidc.IDToken
		pkceVerifier string
		err          error
		idTokenRaw   string
		ok           bool
	)

	// Check provider and client state matches
	returnedState := c.Query("state")
	stateCookie, err := c.Cookie("oidc_state")
	if err != nil || returnedState != stateCookie {
		c.String(http.StatusBadRequest, "Invalid state")
		return
	}

	// Check if the response includes an authz code
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Authorization code not found")
		return
	}

	// Include pkce verifier in exchange
	if pkceVerifier, err = c.Cookie("oidc_pkce"); err != nil {
		c.String(http.StatusBadRequest, "Failed to get PKCE cookie.")
	}

	// Exchange authz code for ID Token
	if token, err = oauth2Config.Exchange(c, code, oauth2.VerifierOption(pkceVerifier)); err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token: %v", err)
		return
	}

	// Extract raw token
	if idTokenRaw, ok = token.Extra("id_token").(string); !ok {
		c.String(http.StatusInternalServerError, "No ID token found")
		return
	}

	// Verify raw token
	if idToken, err = jwtVerifier.Verify(c, idTokenRaw); err != nil {
		c.String(http.StatusInternalServerError, "Failed to verify ID token: %v", err)
		return
	}

	// Parse token claims
	var tokenClaims map[string]interface{}
	if err = idToken.Claims(&tokenClaims); err != nil {
		c.String(http.StatusInternalServerError, "Failed to parse tokenClaims: %v", err)
		return
	}

	var userinfo *oidc.UserInfo
	if userinfo, err = oidcProvider.UserInfo(c, oauth2.StaticTokenSource(token)); err != nil {
		c.String(http.StatusInternalServerError, "Failed to retrieve userinfo claims: %v", err)
		return
	}

	var userinfoClaims map[string]interface{}
	if err = userinfo.Claims(&userinfoClaims); err != nil {
		c.String(http.StatusInternalServerError, "Unable to decode userinfo claims: %v", err)
		return
	}

	// Replace timestamps with formatted date time objects
	formatTimestampClaims(tokenClaims, "auth_time", "exp", "iat")
	formatTimestampClaims(userinfoClaims, "auth_time", "exp", "iat", "updated_at")

	allClaims := make(map[string]struct{})
	for k := range tokenClaims {
		allClaims[k] = struct{}{}
	}
	for k := range userinfoClaims {
		allClaims[k] = struct{}{}
	}

	// Render the HTML template with the tokens and tokenClaims
	c.HTML(http.StatusOK, "callback.tmpl", gin.H{
		"authCodeURL":    authCodeURL,
		"AccessToken":    token.AccessToken,
		"IDToken":        idTokenRaw,
		"tokenClaims":    tokenClaims,
		"userinfoClaims": userinfoClaims,
		"allClaims":      allClaims,
	})
}
