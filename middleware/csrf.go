package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/utils"
)

type CSRFConfig struct {
	HeaderName string
}

var HeaderName string = "X-CSRF-Token"

// CSRF returns the Fiber CSRF middleware with default safe settings.
func CSRF() fiber.Handler {
	return csrf.New(csrf.Config{
		KeyLookup:      "header:" + HeaderName,
		CookieName:     "csrf_", // cookie storing the secret
		CookieSameSite: "Lax",
		CookieHTTPOnly: true,
		CookieSecure:   false,  // set true in production HTTPS
		ContextKey:     "csrf", // name of value stored in c.Locals()
		Expiration:     time.Second * 5,
		//	SingleUseToken:    true,         // token can be used only once
		KeyGenerator: utils.UUIDv4, // use UUIDs for token generation
		ErrorHandler: defaultErrorHandler,
	})
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
