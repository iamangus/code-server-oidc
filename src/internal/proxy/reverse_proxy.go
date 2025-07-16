package proxy

import (
	"fmt"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type ReverseProxy struct {
	targetURL *url.URL
	logger    *zap.SugaredLogger
}

func NewReverseProxy(targetHost string, logger *zap.SugaredLogger) (*ReverseProxy, error) {
	targetURL, err := url.Parse(targetHost)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	return &ReverseProxy{
		targetURL: targetURL,
		logger:    logger,
	}, nil
}

func (rp *ReverseProxy) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Build target URL
		target := fmt.Sprintf("http://%s%s?%s", rp.targetURL.Host, c.Path(), string(c.Request().URI().QueryString()))
		
		// Create proxy request
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)
		
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(resp)
		
		// Copy request
		c.Request().CopyTo(req)
		req.SetRequestURI(target)
		req.Header.SetHost(rp.targetURL.Host)
		
		// Set headers
		req.Header.Set("X-Forwarded-Host", string(c.Request().Host()))
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Real-IP", c.IP())
		
		// Make request
		client := &fasthttp.Client{}
		if err := client.Do(req, resp); err != nil {
			rp.logger.Errorf("Proxy error: %v", err)
			return fiber.NewError(fiber.StatusServiceUnavailable, "Service unavailable")
		}
		
		// Copy response
		resp.CopyTo(c.Response())
		
		return nil
	}
}