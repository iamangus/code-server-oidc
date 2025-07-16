package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
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
			return c.Redirect("/~")
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

	return c.Redirect("/~")
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
	// Check authentication
	sessionID := c.Cookies("session_id")
	if sessionID == "" {
		return c.Redirect("/")
	}

	sessionData, exists := h.sessionStore.GetSession(sessionID)
	if !exists {
		return c.Redirect("/")
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
	
	// Handle path rewriting - we're now at /~ so just use the path as-is
	path := c.Path()
	if path == "/~" {
		path = "/"
	} else if strings.HasPrefix(path, "/~/") {
		path = strings.TrimPrefix(path, "/~")
	}
	
	// Add query parameters
	query := string(c.Context().QueryArgs().QueryString())
	
	// Create proxy request
	target := fmt.Sprintf("%s%s", targetURL, path)
	if query != "" {
		target = fmt.Sprintf("%s?%s", target, query)
	}
	
	h.logger.Infof("Proxying request for user %s to: %s", username, target)
	h.logger.Infof("  Instance details: Port=%d, PID=%d", inst.Port, inst.PID)
	
	// Test if the code-server is actually running
	testURL := fmt.Sprintf("http://localhost:%d", inst.Port)
	h.logger.Debugf("Testing connection to: %s", testURL)
	
	// Use fasthttp to proxy the request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	
	// Copy the original request
	c.Request().CopyTo(req)
	req.SetRequestURI(target)
	req.Header.SetMethod(c.Method())
	req.Header.SetHost(fmt.Sprintf("localhost:%d", inst.Port))
	
	// Clear problematic headers
	req.Header.Del("Connection")
	req.Header.Del("Proxy-Connection")
	
	// Set proxy headers
	req.Header.Set("X-Forwarded-Host", string(c.Request().Host()))
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", c.IP())
	req.Header.Set("X-Forwarded-For", c.IP())
	
	// Make the request with timeout
	client := &fasthttp.Client{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	
	if err := client.Do(req, resp); err != nil {
		h.logger.Errorf("Proxy error to %s: %v", target, err)
		return fiber.NewError(fiber.StatusBadGateway, fmt.Sprintf("Failed to connect to code-server: %v", err))
	}
	
	// Handle redirect cleanup - remove folder parameter from root redirects
	if resp.StatusCode() >= 300 && resp.StatusCode() < 400 {
		location := string(resp.Header.Peek("Location"))
		userHome := fmt.Sprintf("%s/%s", h.config.CodeServer.HomeBase, username)
		if location == "/?folder="+userHome || location == "/?folder="+userHome+"/" {
			resp.Header.Set("Location", "/")
		}
	}
	
	// Copy response back to client
	resp.CopyTo(c.Response())
	
	return nil
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