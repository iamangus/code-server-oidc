package instance

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"oidc-code-server-wrapper/internal/config"
)

type Instance struct {
	Username string
	Port     int
	PID      int
	Cmd      *exec.Cmd
}

type Manager struct {
	config        *config.Config
	logger        *zap.SugaredLogger
	mu            sync.RWMutex
	instances     map[string]*Instance
	portAllocator *PortAllocator
}

type PortAllocator struct {
	start int
	end   int
	used  map[int]bool
	mu    sync.Mutex
}

func NewManager(cfg *config.Config, logger *zap.SugaredLogger) *Manager {
	return &Manager{
		config:        cfg,
		logger:        logger,
		instances:     make(map[string]*Instance),
		portAllocator: NewPortAllocator(cfg.CodeServer.PortRange.Start, cfg.CodeServer.PortRange.End),
	}
}

func NewPortAllocator(start, end int) *PortAllocator {
	return &PortAllocator{
		start: start,
		end:   end,
		used:  make(map[int]bool),
	}
}

func (pa *PortAllocator) Allocate() (int, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	for port := pa.start; port <= pa.end; port++ {
		if !pa.used[port] {
			pa.used[port] = true
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports in range %d-%d", pa.start, pa.end)
}

func (pa *PortAllocator) Release(port int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.used, port)
}

func (m *Manager) StartInstance(username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if instance already exists
	if instance, exists := m.instances[username]; exists {
		if m.isInstanceRunning(instance) {
			return instance.Port, nil
		}
		// Clean up dead instance
		delete(m.instances, username)
		m.portAllocator.Release(instance.Port)
	}

	// Allocate port
	port, err := m.portAllocator.Allocate()
	if err != nil {
		return 0, fmt.Errorf("failed to allocate port: %w", err)
	}

	// Prepare command
	userHome := fmt.Sprintf("%s/%s", m.config.CodeServer.HomeBase, username)
	
	// Check if user home directory exists
	if _, err := os.Stat(userHome); os.IsNotExist(err) {
		m.logger.Warnf("User home directory does not exist: %s", userHome)
		// Try to create it
		if err := os.MkdirAll(userHome, 0755); err != nil {
			m.logger.Errorf("Failed to create user home directory: %v", err)
			return 0, fmt.Errorf("user home directory does not exist and cannot be created: %w", err)
		}
		m.logger.Infof("Created user home directory: %s", userHome)
	}
	
	// Check if code-server executable exists
	if _, err := os.Stat(m.config.CodeServer.Executable); os.IsNotExist(err) {
		m.logger.Errorf("Code-server executable not found: %s", m.config.CodeServer.Executable)
		return 0, fmt.Errorf("code-server executable not found: %s", m.config.CodeServer.Executable)
	}
	
	// Build the command to run as the user
	command := fmt.Sprintf("%s --auth none --bind-addr 127.0.0.1:%d --disable-telemetry '%s'",
		m.config.CodeServer.Executable, port, userHome)
	
	// Use su to run as the user
	cmd := exec.Command("su", username, "--command", command)

	// Set environment - su will handle most user environment variables
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", userHome),
		fmt.Sprintf("USER=%s", username),
	)

	// Capture stdout and stderr for debugging
	cmd.Stdout = &debugWriter{logger: m.logger, prefix: fmt.Sprintf("[code-server:%s:stdout]", username)}
	cmd.Stderr = &debugWriter{logger: m.logger, prefix: fmt.Sprintf("[code-server:%s:stderr]", username)}

	// Log the exact command being executed
	m.logger.Infof("Starting code-server for user %s:", username)
	m.logger.Infof("  Command: su %s --command \"%s --auth none --bind-addr 127.0.0.1:%d --disable-telemetry '%s'\"",
		username, m.config.CodeServer.Executable, port, userHome)
	m.logger.Infof("  Working directory: %s", userHome)
	m.logger.Infof("  Environment: HOME=%s, USER=%s", userHome, username)

	// Start process
	if err := cmd.Start(); err != nil {
		m.portAllocator.Release(port)
		m.logger.Errorf("Failed to start code-server for user %s: %v", username, err)
		return 0, fmt.Errorf("failed to start code-server: %w", err)
	}

	// Wait for code-server to actually start listening
	m.logger.Infof("Waiting for code-server to start listening on port %d...", port)
	
	// Give it more time to start
	maxWait := 10 * time.Second
	start := time.Now()
	
	// Check if the port is actually listening
	for time.Since(start) < maxWait {
		if m.isPortListening(port) {
			m.logger.Infof("Code-server is now listening on port %d", port)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	
	if !m.isPortListening(port) {
		m.portAllocator.Release(port)
		m.logger.Errorf("Code-server failed to start listening on port %d after %v", port, maxWait)
		return 0, fmt.Errorf("code-server failed to start listening on port %d", port)
	}
	
	m.logger.Infof("Code-server started successfully for user %s (PID: %d, Port: %d)", username, cmd.Process.Pid, port)

	instance := &Instance{
		Username: username,
		Port:     port,
		PID:      cmd.Process.Pid,
		Cmd:      cmd,
	}

	m.instances[username] = instance
	m.logger.Infof("Started code-server for user %s on port %d (PID: %d)", username, port, cmd.Process.Pid)

	return port, nil
}

func (m *Manager) StopInstance(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	instance, exists := m.instances[username]
	if !exists {
		return fmt.Errorf("no instance found for user %s", username)
	}

	if err := m.stopInstance(instance); err != nil {
		return err
	}

	delete(m.instances, username)
	m.portAllocator.Release(instance.Port)
	m.logger.Infof("Stopped code-server for user %s", username)

	return nil
}

func (m *Manager) GetInstance(username string) (*Instance, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	instance, exists := m.instances[username]
	if !exists {
		return nil, false
	}

	if !m.isInstanceRunning(instance) {
		return nil, false
	}

	return instance, true
}

func (m *Manager) isInstanceRunning(instance *Instance) bool {
	return m.isProcessRunning(instance.PID)
}

func (m *Manager) isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix systems, signal 0 can be used to check if process exists
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func (m *Manager) isPortListening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (m *Manager) stopInstance(instance *Instance) error {
	if instance.Cmd != nil && instance.Cmd.Process != nil {
		return instance.Cmd.Process.Kill()
	}
	return nil
}

func (m *Manager) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupDeadInstances()
		}
	}
}

func (m *Manager) cleanupDeadInstances() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for username, instance := range m.instances {
		if !m.isInstanceRunning(instance) {
			m.logger.Infof("Cleaning up dead instance for user %s", username)
			delete(m.instances, username)
			m.portAllocator.Release(instance.Port)
		}
	}
}

type debugWriter struct {
	logger *zap.SugaredLogger
	prefix string
}

func (w *debugWriter) Write(p []byte) (n int, err error) {
	w.logger.Infof("%s %s", w.prefix, string(p))
	return len(p), nil
}

func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for username, instance := range m.instances {
		m.logger.Infof("Shutting down instance for user %s", username)
		m.stopInstance(instance)
		delete(m.instances, username)
		m.portAllocator.Release(instance.Port)
	}
}