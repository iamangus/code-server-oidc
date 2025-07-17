package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"

	"oidc-code-server-wrapper/internal/auth"
	"oidc-code-server-wrapper/internal/config"
	"oidc-code-server-wrapper/internal/instance"
	"oidc-code-server-wrapper/internal/session"
)

type Handlers struct {
	config          *config.Config
	sessionStore    *session.MemoryStore
	instanceManager *instance.Manager
	oidcAuth        *auth.OIDCAuth
	logger          *zap.SugaredLogger
}

func New(cfg *config.Config, sessionStore *session.MemoryStore, instanceManager *instance.Manager, oidcAuth *auth.OIDCAuth, logger *zap.SugaredLogger) *Handlers {
	return &Handlers{
		config:          cfg,
		sessionStore:    sessionStore,
		instanceManager: instanceManager,
		oidcAuth:        oidcAuth,
		logger:          logger,
	}
}

func (h *Handlers) Landing(c *fiber.Ctx) error {
	sessionID := c.Cookies("session_id")
	if sessionID != "" {
		if _, exists := h.sessionStore.GetSession(sessionID); exists {
			// Check if there's a redirect URL in the query parameters
			queryRedirect := c.Query("redirect")
			if queryRedirect != "" {
				// Validate the redirect URL to prevent open redirect vulnerabilities
				parsedURL, err := url.Parse(queryRedirect)
				if err == nil && parsedURL.Path != "" && !parsedURL.IsAbs() {
					// Only allow relative paths
					return c.Redirect(queryRedirect)
				}
			}
			
			// Check for redirect URL after login
			redirectURL := "/~"
			if redirectCookie := c.Cookies("redirect_after_login"); redirectCookie != "" {
				redirectURL = redirectCookie
				// Clear the redirect cookie
				c.Cookie(&fiber.Cookie{
					Name:   "redirect_after_login",
					Value:  "",
					MaxAge: -1,
				})
			}
			
			return c.Redirect(redirectURL)
		}
	}

	return c.Render("landing", fiber.Map{
		"Title": "Code-Server Login",
	})
}

func (h *Handlers) Login(c *fiber.Ctx) error {
	// Generate state for CSRF protection
	state, err := h.oidcAuth.GenerateRandomString(32)
	if err != nil {
		h.logger.Errorf("Failed to generate state: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to generate state")
	}

	// Store state in session
	c.Cookie(&fiber.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   300, // 5 minutes
	})

	// Check for redirect parameter and store it
	redirectURL := c.Query("redirect")
	if redirectURL != "" {
		// Store redirect URL in a cookie for use after authentication
		c.Cookie(&fiber.Cookie{
			Name:     "redirect_after_login",
			Value:    redirectURL,
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
			MaxAge:   300, // 5 minutes
		})
	}

	// Generate authorization URL
	authURL := h.oidcAuth.GetAuthURL(state)
	
	return c.Redirect(authURL, fiber.StatusTemporaryRedirect)
}

func (h *Handlers) Callback(c *fiber.Ctx) error {
	// Verify state
	state := c.Query("state")
	cookieState := c.Cookies("oauth_state")
	if state != cookieState {
		h.logger.Error("Invalid state parameter")
		return c.Status(fiber.StatusBadRequest).SendString("Invalid state parameter")
	}

	// Clear state cookie
	c.Cookie(&fiber.Cookie{
		Name:   "oauth_state",
		Value:  "",
		MaxAge: -1,
	})

	// Get authorization code
	code := c.Query("code")
	if code == "" {
		h.logger.Error("Missing authorization code")
		return c.Status(fiber.StatusBadRequest).SendString("Missing authorization code")
	}

	// Exchange code for tokens
	ctx := context.Background()
	token, err := h.oidcAuth.ExchangeCode(ctx, code)
	if err != nil {
		h.logger.Errorf("Failed to exchange code for token: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Authentication failed")
	}

	// Get user info
	userInfo, err := h.oidcAuth.GetUserInfo(ctx, token)
	if err != nil {
		h.logger.Errorf("Failed to get user info: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get user information")
	}

	if userInfo.Email == "" {
		h.logger.Error("No email found in user profile")
		return c.Status(fiber.StatusInternalServerError).SendString("No email found in user profile")
	}

	username := h.oidcAuth.GetUsername(userInfo)

	// Create session
	sessionID := generateRandomString(32)
	sessionData := &session.SessionData{
		Username:     username,
		Email:        userInfo.Email,
		Token:        token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(h.config.Session.Timeout) * time.Second),
		LastActivity: time.Now(),
	}
	h.sessionStore.SetSession(sessionID, sessionData)

	// Set session cookie
	c.Cookie(&fiber.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		MaxAge:   h.config.Session.Timeout,
	})

	// Start code-server instance
	port, err := h.instanceManager.StartInstance(username)
	if err != nil {
		h.logger.Errorf("Failed to start code-server for %s: %v", username, err)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to start code-server")
	}

	// Store user data
	userData := &session.UserData{
		Username:     username,
		Port:         port,
		LastActivity: time.Now(),
	}
	h.sessionStore.SetUser(username, userData)

	// Check for redirect URL after login
	redirectURL := "/~"
	if redirectCookie := c.Cookies("redirect_after_login"); redirectCookie != "" {
		redirectURL = redirectCookie
		// Clear the redirect cookie
		c.Cookie(&fiber.Cookie{
			Name:   "redirect_after_login",
			Value:  "",
			MaxAge: -1,
		})
	}
	
	return c.Redirect(redirectURL)
}

func (h *Handlers) Logout(c *fiber.Ctx) error {
	sessionID := c.Cookies("session_id")
	if sessionID != "" {
		if sessionData, exists := h.sessionStore.GetSession(sessionID); exists {
			// Stop code-server instance
			h.instanceManager.StopInstance(sessionData.Username)
			
			// Clean up session and user data
			h.sessionStore.DeleteSession(sessionID)
			h.sessionStore.DeleteUser(sessionData.Username)
		}
	}

	// Clear session cookie
	c.Cookie(&fiber.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
	})

	return c.Redirect("/")
}

func (h *Handlers) ProxyUser(c *fiber.Ctx) error {
	path := c.Path()
	
	// Skip authentication for landing page and auth routes
	// These should be handled by their specific route handlers
	if path == "/" || path == "/auth/login" || path == "/auth/callback" ||
	   path == "/auth/logout" || path == "/health" {
		return c.Next()
	}
	
	// Check if this is a static asset request
	isStaticAsset := strings.Contains(path, "/static/") ||
		strings.Contains(path, "/stable-") ||
		strings.HasSuffix(path, ".css") ||
		strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".svg") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".woff") ||
		strings.HasSuffix(path, ".woff2") ||
		strings.HasSuffix(path, ".ttf")
	
	// Check authentication
	sessionID := c.Cookies("session_id")
	if sessionID == "" {
		// For static assets, return 404 to let browser handle it gracefully
		// This prevents redirect loops for assets that shouldn't require auth
		if isStaticAsset {
			return c.Status(fiber.StatusNotFound).SendString("Not found")
		}
		// Preserve the original path for redirect after login
		originalPath := c.Path()
		if c.Context().QueryArgs().String() != "" {
			originalPath += "?" + c.Context().QueryArgs().String()
		}
		redirectURL := "/?redirect=" + url.QueryEscape(originalPath)
		return c.Redirect(redirectURL)
	}

	sessionData, exists := h.sessionStore.GetSession(sessionID)
	if !exists {
		// For static assets, return 404
		if isStaticAsset {
			return c.Status(fiber.StatusNotFound).SendString("Not found")
		}
		// Preserve the original path for redirect after login
		originalPath := c.Path()
		if c.Context().QueryArgs().String() != "" {
			originalPath += "?" + c.Context().QueryArgs().String()
		}
		redirectURL := "/?redirect=" + url.QueryEscape(originalPath)
		return c.Redirect(redirectURL)
	}

	username := sessionData.Username
	
	// Validate username format
	if !isValidUsername(username) {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid username")
	}

	// Update last activity
	sessionData.LastActivity = time.Now()
	h.sessionStore.SetSession(sessionID, sessionData)

	// Get or start instance
	userData, exists := h.sessionStore.GetUser(username)
	if !exists {
		h.logger.Infof("Starting new code-server instance for user: %s", username)
		port, err := h.instanceManager.StartInstance(username)
		if err != nil {
			h.logger.Errorf("Failed to start instance for %s: %v", username, err)
			return c.Status(fiber.StatusInternalServerError).SendString(fmt.Sprintf("Failed to start code-server: %v", err))
		}
		
		userData = &session.UserData{
			Username:     username,
			Port:         port,
			LastActivity: time.Now(),
		}
		h.sessionStore.SetUser(username, userData)
		h.logger.Infof("Successfully started instance for user %s on port %d", username, port)
	} else {
		h.logger.Infof("Using existing instance for user %s on port %d", username, userData.Port)
	}

	// Check if instance is running
	inst, exists := h.instanceManager.GetInstance(username)
	if !exists {
		port, err := h.instanceManager.StartInstance(username)
		if err != nil {
			h.logger.Errorf("Failed to restart instance for %s: %v", username, err)
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to restart code-server")
		}
		userData.Port = port
		h.sessionStore.SetUser(username, userData)
		inst = &instance.Instance{
			Username: username,
			Port:     port,
		}
	}

	// Build target URL
	targetURL := fmt.Sprintf("http://localhost:%d", inst.Port)
	
	h.logger.Infof("  Instance details: Port=%d, PID=%d", inst.Port, inst.PID)
	
	// Handle path rewriting
	path = c.Path()
	var folderPath string
	
	if path == "/~" {
		path = "/"
		folderPath = fmt.Sprintf("%s/%s", h.config.CodeServer.HomeBase, username)
	} else if strings.HasPrefix(path, "/~/") {
		path = strings.TrimPrefix(path, "/~/")
		if path == "" {
			path = "/"
		}
		// Don't add folder parameter for subdirectories
	}
	
	// Build the final target URL
	// Ensure path starts with a slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target := fmt.Sprintf("%s%s", targetURL, path)
	
	// Build query parameters
	query := c.Context().QueryArgs().String()
	if folderPath != "" {
		if query != "" {
			query += "&"
		}
		query += "folder=" + url.QueryEscape(folderPath)
	}
	
	if query != "" {
		target += "?" + query
	}
	
	// Check if this is a WebSocket upgrade request
	isWebSocket := strings.Contains(strings.ToLower(c.Get("Connection")), "upgrade") &&
		strings.ToLower(c.Get("Upgrade")) == "websocket"
	
	if isWebSocket {
		h.logger.Infof("Handling WebSocket upgrade for user %s", username)
	}
	
	h.logger.Infof("Proxying request for user %s to: %s", username, target)
	
	// Use proper HTTP proxy with WebSocket support
	return h.proxyRequest(c, target, username)
}

func (h *Handlers) Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
		"timestamp": time.Now().Unix(),
	})
}


func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}


func (h *Handlers) proxyRequest(c *fiber.Ctx, targetURL string, username string) error {
	// Parse the target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		h.logger.Errorf("Invalid target URL: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "Invalid target URL")
	}
	
	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// Check if this is a WebSocket upgrade request
	isWebSocket := strings.Contains(strings.ToLower(c.Get("Connection")), "upgrade") &&
		strings.ToLower(c.Get("Upgrade")) == "websocket"
	
	if isWebSocket {
		h.logger.Infof("Handling WebSocket upgrade for user %s to %s", username, targetURL)
	}
	
	// Update the director to handle path and query parameters
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		
		// Handle path rewriting
		path := c.Path()
		
		if path == "/~" {
			path = "/"
			// Add folder parameter for root access
			folderPath := fmt.Sprintf("%s/%s", h.config.CodeServer.HomeBase, username)
			query := req.URL.Query()
			query.Set("folder", folderPath)
			req.URL.RawQuery = query.Encode()
		} else if strings.HasPrefix(path, "/~/") {
			// Remove the /~/ prefix and keep the rest of the path
			path = strings.TrimPrefix(path, "/~/")
			if path == "" {
				path = "/"
			}
		} else if strings.HasPrefix(path, "/stable-") {
			// Handle stable endpoints directly without modification
			// Keep the original path for stable endpoints
			h.logger.Infof("Proxying stable endpoint: %s", path)
		}
		
		req.URL.Path = path
		req.Host = fmt.Sprintf("localhost:%d", target.Port())
		
		// Copy headers from Fiber context
		c.Request().Header.VisitAll(func(key, value []byte) {
			req.Header.Set(string(key), string(value))
		})
		
		// Set proxy headers
		req.Header.Set("X-Forwarded-Host", string(c.Context().Host()))
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Real-IP", c.IP())
		req.Header.Set("X-Forwarded-For", c.IP())
	}
	
	// Create HTTP request from Fiber context
	httpReq, httpErr := http.NewRequest(c.Method(), c.OriginalURL(), nil)
	if httpErr != nil {
		h.logger.Errorf("Failed to create HTTP request: %v", httpErr)
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create request")
	}
	
	// Copy headers - ensure WebSocket headers are preserved
	c.Request().Header.VisitAll(func(key, value []byte) {
		httpReq.Header.Set(string(key), string(value))
	})
	
	// Apply director
	proxy.Director(httpReq)
	
	// Create a custom response writer that writes directly to Fiber
	rw := &fiberProxyWriter{ctx: c}
	
	// Serve the request
	proxy.ServeHTTP(rw, httpReq)
	
	return nil
}

// fiberProxyWriter implements http.ResponseWriter for Fiber proxy
type fiberProxyWriter struct {
	ctx     *fiber.Ctx
	headers http.Header
}

func (w *fiberProxyWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}

func (w *fiberProxyWriter) WriteHeader(statusCode int) {
	w.ctx.Status(statusCode)
	
	// Copy all headers from the response to Fiber context
	if w.headers != nil {
		for key, values := range w.headers {
			for _, value := range values {
				w.ctx.Set(key, value)
			}
		}
	}
}

func (w *fiberProxyWriter) Write(b []byte) (int, error) {
	return w.ctx.Write(b)
}

func isValidUsername(username string) bool {
	if username == "" {
		return false
	}
	
	// Basic validation - alphanumeric and underscore only
	for _, char := range username {
		if !(char >= 'a' && char <= 'z') &&
		   !(char >= 'A' && char <= 'Z') &&
		   !(char >= '0' && char <= '9') &&
		   char != '_' && char != '-' {
			return false
		}
	}
	
	return true
}