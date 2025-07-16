# Configuration Guide

The application uses **environment variables only** for configuration.

## Environment Variables

### Required Environment Variables

```bash
# OIDC Configuration (Required)
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_PROVIDER_URL=https://accounts.google.com
OIDC_REDIRECT_URL=http://localhost:3000/auth/callback

# Session Configuration (Required)
SESSION_SECRET=your-secure-session-secret
```

### Optional Environment Variables

```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=3000

# Code Server Configuration
CODE_SERVER_EXECUTABLE=/usr/bin/code-server
CODE_SERVER_PORT_RANGE_START=10000
CODE_SERVER_PORT_RANGE_END=20000
CODE_SERVER_HOME_BASE=/home

# Session Configuration
SESSION_TIMEOUT=3600

# Logging Configuration
LOGGING_LEVEL=info
LOGGING_FORMAT=json
```

## Configuration Examples

### Development
```bash
export OIDC_CLIENT_ID=your-dev-client-id
export OIDC_CLIENT_SECRET=your-dev-client-secret
export OIDC_PROVIDER_URL=https://accounts.google.com
export OIDC_REDIRECT_URL=http://localhost:3000/auth/callback
export SESSION_SECRET=dev-session-secret
```

### Production
```bash
# Use secure secrets in production
export OIDC_CLIENT_ID=your-prod-client-id
export OIDC_CLIENT_SECRET=your-prod-client-secret
export OIDC_PROVIDER_URL=https://accounts.google.com
export OIDC_REDIRECT_URL=https://code.yourdomain.com/auth/callback
export SESSION_SECRET=your-secure-production-secret
export SERVER_PORT=8080
```

### Docker
```bash
# docker-compose.yml
version: '3.8'
services:
  code-server-wrapper:
    image: your-image
    environment:
      - OIDC_CLIENT_ID=your-client-id
      - OIDC_CLIENT_SECRET=your-client-secret
      - OIDC_PROVIDER_URL=https://accounts.google.com
      - OIDC_REDIRECT_URL=https://code.yourdomain.com/auth/callback
      - SESSION_SECRET=your-session-secret
      - SERVER_PORT=8080
    ports:
      - "8080:8080"
```

## Required Configuration

At minimum, you must provide:
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_PROVIDER_URL`
- `SESSION_SECRET`