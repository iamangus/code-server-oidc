package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"go.uber.org/zap"

	"oidc-code-server-wrapper/internal/auth"
	"oidc-code-server-wrapper/internal/config"
	"oidc-code-server-wrapper/internal/handlers"
	"oidc-code-server-wrapper/internal/instance"
	"oidc-code-server-wrapper/internal/session"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found, using environment variables")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	loggerConfig := zap.NewProductionConfig()
	if cfg.Logging.Level == "debug" {
		loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	
	zapLogger, err := loggerConfig.Build()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer zapLogger.Sync()

	logger := zapLogger.Sugar()

	// Ensure session secret is set for Goth
	if cfg.Session.Secret != "" {
		os.Setenv("SESSION_SECRET", cfg.Session.Secret)
		logger.Infof("SESSION_SECRET set from config: %s", cfg.Session.Secret[:8]+"...")
	} else {
		logger.Warn("SESSION_SECRET is empty!")
	}

	// Initialize components
	sessionStore := session.NewMemoryStore()
	instanceManager := instance.NewManager(cfg, logger)
	oidcAuth := auth.NewOIDCAuth(cfg, logger)

	// Initialize Fiber app
	engine := html.New("./web/templates", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			logger.Errorf("Request error: %v", err)
			return c.Status(fiber.StatusInternalServerError).Render("error", fiber.Map{
				"Error": "Internal server error",
			})
		},
	})

	// Middleware
	app.Use(recover.New())

	// Initialize handlers
	h := handlers.New(cfg, sessionStore, instanceManager, oidcAuth, logger)

	// Routes
	app.Get("/", h.Landing)
	app.Get("/auth/login", h.Login)
	app.Get("/auth/callback", h.Callback)
	app.Get("/auth/logout", h.Logout)
	app.Get("/health", h.Health)
	
	// User routing - must be last as it's a catch-all
	app.Use("/~/:username", h.ProxyUser)

	// Start cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go sessionStore.StartCleanup(ctx)
	go instanceManager.StartCleanup(ctx)

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Infof("Starting server on %s", addr)

	go func() {
		if err := app.Listen(addr); err != nil {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		logger.Errorf("Error during shutdown: %v", err)
	}

	// Cleanup instances
	instanceManager.Shutdown()

	logger.Info("Server stopped")
}