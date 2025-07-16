package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Server     ServerConfig
	OIDC       OIDCConfig
	CodeServer CodeServerConfig
	Session    SessionConfig
	Logging    LoggingConfig
}

type ServerConfig struct {
	Host string
	Port int
}

type OIDCConfig struct {
	ProviderURL  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type CodeServerConfig struct {
	Executable string
	PortRange  PortRangeConfig
	HomeBase   string
}

type PortRangeConfig struct {
	Start int
	End   int
}

type SessionConfig struct {
	Secret  string
	Timeout int
}

type LoggingConfig struct {
	Level  string
	Format string
}

func Load() (*Config, error) {
	cfg := &Config{}

	// Server configuration
	cfg.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")
	cfg.Server.Port = getEnvAsInt("SERVER_PORT", 3000)

	// OIDC configuration
	cfg.OIDC.ClientID = getEnv("OIDC_CLIENT_ID", "")
	cfg.OIDC.ClientSecret = getEnv("OIDC_CLIENT_SECRET", "")
	cfg.OIDC.ProviderURL = getEnv("OIDC_PROVIDER_URL", "")
	cfg.OIDC.RedirectURL = getEnv("OIDC_REDIRECT_URL", "")

	// Code server configuration
	cfg.CodeServer.Executable = getEnv("CODE_SERVER_EXECUTABLE", "/usr/bin/code-server")
	cfg.CodeServer.PortRange.Start = getEnvAsInt("CODE_SERVER_PORT_RANGE_START", 10000)
	cfg.CodeServer.PortRange.End = getEnvAsInt("CODE_SERVER_PORT_RANGE_END", 20000)
	cfg.CodeServer.HomeBase = getEnv("CODE_SERVER_HOME_BASE", "/home")

	// Session configuration
	cfg.Session.Secret = getEnv("SESSION_SECRET", "")
	cfg.Session.Timeout = getEnvAsInt("SESSION_TIMEOUT", 3600)

	// Logging configuration
	cfg.Logging.Level = getEnv("LOGGING_LEVEL", "info")
	cfg.Logging.Format = getEnv("LOGGING_FORMAT", "json")

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func validate(cfg *Config) error {
	if cfg.OIDC.ClientID == "" {
		return fmt.Errorf("OIDC_CLIENT_ID is required")
	}
	if cfg.OIDC.ClientSecret == "" {
		return fmt.Errorf("OIDC_CLIENT_SECRET is required")
	}
	if cfg.OIDC.ProviderURL == "" {
		return fmt.Errorf("OIDC_PROVIDER_URL is required")
	}
	if cfg.Session.Secret == "" {
		return fmt.Errorf("SESSION_SECRET is required")
	}
	if cfg.CodeServer.PortRange.Start >= cfg.CodeServer.PortRange.End {
		return fmt.Errorf("CODE_SERVER_PORT_RANGE_START must be less than CODE_SERVER_PORT_RANGE_END")
	}
	return nil
}