package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

type CSRFConfig struct {
	HeaderName string
	SecretKey  string
	TokenTTL   time.Duration
}

var HeaderName string = "X-CSRF-Token"
var SecretKey string = "your-secret-key-change-in-production" // Change this in production!
var TokenTTL time.Duration = 10 * time.Second                 // Token validity period

// CSRF returns the Fiber CSRF middleware with custom token generation including timestamp and user agent.
func CSRF() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Generate custom token with timestamp and user agent
		token := customTokenGenerator(c)

		// Store token in context
		c.Locals("csrf", token)

		// For non-safe methods, validate the token
		if c.Method() != "GET" && c.Method() != "HEAD" && c.Method() != "OPTIONS" {
			_, err := customTokenExtractor(c)
			if err != nil {
				return defaultErrorHandler(c, err)
			}
		}

		return c.Next()
	}
}

// customTokenGenerator generates a CSRF token with timestamp and user agent signature
func customTokenGenerator(c *fiber.Ctx) string {
	// Get current timestamp
	timestamp := time.Now().Unix()

	// Get user agent
	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		userAgent = "unknown"
	}

	// Generate base token
	baseToken := utils.UUIDv4()

	// Create signature payload: baseToken|timestamp|userAgent
	payload := fmt.Sprintf("%s|%d|%s", baseToken, timestamp, userAgent)

	// Generate HMAC signature
	signature := generateSignature(payload, SecretKey)

	// Combine: baseToken.timestamp.signature
	token := fmt.Sprintf("%s.%d.%s", baseToken, timestamp, signature)

	return token
}

// customTokenExtractor validates the token signature including timestamp and user agent
func customTokenExtractor(c *fiber.Ctx) (string, error) {
	// Get token from header
	token := c.Get(HeaderName)
	if token == "" {
		return "", fmt.Errorf("CSRF token not found in header")
	}

	// Parse token: baseToken.timestamp.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	baseToken := parts[0]
	timestampStr := parts[1]
	providedSignature := parts[2]

	// Parse timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp in token")
	}

	// Check if token is expired
	tokenTime := time.Unix(timestamp, 0)
	if time.Since(tokenTime) > TokenTTL {
		return "", fmt.Errorf("token expired")
	}

	// Get current user agent
	userAgent := c.Get("User-Agent")
	if userAgent == "" {
		userAgent = "unknown"
	}

	// Recreate signature payload
	payload := fmt.Sprintf("%s|%d|%s", baseToken, timestamp, userAgent)

	// Generate expected signature
	expectedSignature := generateSignature(payload, SecretKey)

	// Compare signatures
	if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
		return "", fmt.Errorf("invalid token signature")
	}

	// Return the base token for internal use
	return baseToken, nil
}

// generateSignature creates an HMAC-SHA256 signature for the given payload
func generateSignature(payload, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateCSRFToken(c *fiber.Ctx) error {
	token := c.Locals("csrf")
	if token == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "CSRF token not found",
		})
	}
	return c.JSON(fiber.Map{
		"csrf_token": token,
	})
}

func defaultErrorHandler(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error": "CSRF token invalid or missing",
	})
}

// CsrfFromHeader extracts the CSRF token from the specified header.
func CsrfFromHeader(headerName string) func(*fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		return c.Get(headerName), nil
	}
}
