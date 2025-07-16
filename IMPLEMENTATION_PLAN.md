# Implementation Plan - OIDC Code-Server Wrapper

## Phase 1: Project Setup
1. Initialize Go module
2. Create directory structure
3. Set up configuration management
4. Add basic logging

## Phase 2: Core Components
1. **Configuration** (`internal/config`)
   - YAML configuration loading
   - Environment variable overrides
   - Validation

2. **Session Management** (`internal/session`)
   - In-memory store with mutex
   - Session cleanup goroutine
   - User data tracking

3. **OIDC Authentication** (`internal/auth`)
   - Provider configuration
   - Login/callback handlers
   - User profile extraction

4. **Instance Manager** (`internal/instance`)
   - Port allocation
   - Process management
   - Health checks
   - Cleanup

5. **Reverse Proxy** (`internal/proxy`)
   - URL rewriting
   - WebSocket support
   - Error handling

## Phase 3: Web Interface
1. **Landing Page**
   - Simple HTML/CSS
   - OIDC login button
   - Error display

2. **Routes**
   - Main application routes
   - Health endpoints
   - Static file serving

## Phase 4: Integration & Testing
1. **Docker Configuration**
2. **Health Checks**
3. **Error Handling**
4. **Documentation**

## Implementation Order

### Step 1: Foundation
- [ ] Create project structure
- [ ] Add configuration management
- [ ] Set up logging

### Step 2: Session & Auth
- [ ] Implement in-memory session store
- [ ] Add OIDC authentication flow
- [ ] Create user management

### Step 3: Instance Management
- [ ] Build code-server instance manager
- [ ] Add port allocation logic
- [ ] Implement health monitoring

### Step 4: Proxy & Routes
- [ ] Create reverse proxy
- [ ] Add URL rewriting
- [ ] Handle WebSocket connections

### Step 5: Web Interface
- [ ] Build landing page
- [ ] Add static file serving
- [ ] Style the interface

### Step 6: Final Polish
- [ ] Add comprehensive error handling
- [ ] Create Docker configuration
- [ ] Write documentation
- [ ] Add health checks

## Testing Strategy

1. **Unit Tests**
   - Configuration loading
   - Session management
   - URL parsing

2. **Integration Tests**
   - OIDC flow
   - Instance lifecycle
   - Proxy routing

3. **Manual Testing**
   - End-to-end flow
   - Multiple users
   - Session timeout

## Deployment Checklist

- [ ] Build Docker image
- [ ] Configure environment variables
- [ ] Set up OIDC provider
- [ ] Configure reverse proxy
- [ ] Test user flow
- [ ] Monitor resource usage