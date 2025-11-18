package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
)

// CSRF returns the Fiber CSRF middleware with default safe settings.
func CSRF() fiber.Handler {
	return csrf.New(csrf.Config{
		KeyLookup:      "header:X-CSRF-Token", // frontend sends token in this header
		CookieName:     "csrf_",               // cookie storing the secret
		CookieHTTPOnly: true,
		CookieSecure:   false,  // set true in production HTTPS
		ContextKey:     "csrf", // name of value stored in c.Locals()
	})
}
