# OIDC Code-Server Wrapper

A Go-based OIDC authentication wrapper for dynamically managing code-server instances per user. This application provides secure authentication and automatic code-server instance management for multiple users.

## Features

- **OIDC Authentication**: Secure login with Google OAuth2
- **Dynamic Instance Management**: Automatic code-server startup per user
- **Port Allocation**: Dynamic port assignment (10000-20000 range)
- **Session Management**: In-memory session storage with cleanup
- **URL Routing**: Clean URL structure (`/~username/path`)
- **Health Monitoring**: Built-in health checks and monitoring

## Quick Start

### Prerequisites

- Go 1.21+
- code-server installed
- Google OAuth2 credentials

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd oidc-code-server-wrapper
```

2. **Install dependencies**:
```bash
go mod download
```

3. **Configure OAuth2**:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Create a new OAuth2 credential
   - Set redirect URI to `http://localhost:3000/auth/callback`

4. **Set environment variables**:
```bash
export OIDC_CLIENT_ID="your-client-id"
export OIDC_CLIENT_SECRET="your-client-secret"
export OIDC_PROVIDER_URL="https://accounts.google.com"
```

5. **Run the application**:
```bash
go run cmd/wrapper/main.go
```

### Docker Deployment

1. **Build the Docker image**:
```bash
docker build -t oidc-code-server-wrapper .
```

2. **Run with Docker**:
```bash
docker run -d \
  -p 3000:3000 \
  -e OIDC_CLIENT_ID="your-client-id" \
  -e OIDC_CLIENT_SECRET="your-client-secret" \
  -e OIDC_PROVIDER_URL="https://accounts.google.com" \
  -v /home:/home \
  oidc-code-server-wrapper
```

## Configuration

The application supports **two configuration methods** with environment variables taking precedence over the config file.

### Quick Configuration

**For production (recommended):** Use environment variables:
```bash
export OIDC_CLIENT_ID="your-google-client-id"
export OIDC_CLIENT_SECRET="your-google-client-secret"
export OIDC_PROVIDER_URL="https://accounts.google.com"
```

**For development:** Use `config.yaml` file.

### Configuration Priority

1. **Environment variables** (highest priority)
2. **config.yaml** file (fallback)
3. **Built-in defaults**

### Required Configuration

| Source | Required Values |
|--------|-----------------|
| Environment OR config.yaml | `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_PROVIDER_URL` |

### Full Configuration Options

See [CONFIGURATION.md](CONFIGURATION.md) for complete configuration details.

## Usage

### User Flow

1. **Access the application**: Navigate to `http://localhost:3000`
2. **Login**: Click "Sign in with Google"
3. **Access code-server**: After authentication, you'll be redirected to `/~yourusername`
4. **Work with files**: Use the full VS Code interface in your browser

### URL Structure

- **Landing page**: `http://localhost:3000/`
- **User workspace**: `http://localhost:3000/~username`
- **Specific folder**: `http://localhost:3000/~username/path/to/folder`
- **Health check**: `http://localhost:3000/health`

### Logout

Navigate to `http://localhost:3000/auth/logout` to end your session and stop your code-server instance.

## Reverse Proxy Configuration

### Traefik Example

```yaml
# traefik.yml
http:
  routers:
    code-server:
      rule: "Host(`code.yourdomain.com`)"
      service: code-server
      tls:
        certResolver: letsencrypt
  
  services:
    code-server:
      loadBalancer:
        servers:
          - url: "http://localhost:3000"
```

### Nginx Example

```nginx
server {
    listen 443 ssl;
    server_name code.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Considerations

- **User Isolation**: Each user gets their own code-server instance
- **Home Directory**: Users can only access their own home directory
- **Session Timeout**: Sessions expire after configured timeout
- **HTTPS**: Always use HTTPS in production
- **Rate Limiting**: Consider adding rate limiting for production use

## Monitoring

### Health Checks

- **Application health**: `GET /health`
- **Process monitoring**: Automatic cleanup of dead instances
- **Session cleanup**: Automatic cleanup of expired sessions

### Logging

The application uses structured logging with configurable levels:
- **info**: General application events
- **error**: Error conditions
- **debug**: Detailed debugging information

## Troubleshooting

### Common Issues

1. **"No available ports"**: Increase port range in config
2. **"Authentication failed"**: Check OAuth2 credentials
3. **"code-server not found"**: Ensure code-server is installed and in PATH
4. **"Permission denied"**: Check file permissions for home directories

### Debug Mode

Enable debug logging:
```bash
export WRAPPER_LOGGING_LEVEL=debug
```

### Check Logs

```bash
# View logs
docker logs <container-id>

# Or if running directly
./wrapper 2>&1 | tee wrapper.log
```

## Development

### Project Structure

```
oidc-code-server-wrapper/
├── cmd/wrapper/main.go          # Application entry point
├── internal/
│   ├── auth/oidc.go            # OIDC authentication
│   ├── config/config.go        # Configuration management
│   ├── handlers/handlers.go    # HTTP handlers
│   ├── instance/manager.go     # Code-server lifecycle
│   ├── proxy/reverse_proxy.go  # HTTP routing
│   └── session/store.go        # In-memory storage
├── web/templates/              # HTML templates
├── config.yaml                 # Configuration file
├── Dockerfile                  # Container image
└── README.md                   # This file
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details