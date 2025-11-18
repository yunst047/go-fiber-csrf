package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"go-fiber-csrf/middleware"
)

func main() {
	app := fiber.New()

	// CORS (required if frontend is separate)
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:3000",
		AllowHeaders:     "X-CSRF-Token, Content-Type",
	}))

	// CSRF middleware
	app.Use(middleware.CSRF())

	// Endpoint to GET current csrf token
	app.Get("/csrf-token", func(c *fiber.Ctx) error {
		token := c.Locals("csrf").(string)
		return c.JSON(fiber.Map{
			"csrf_token": token,
		})
	})

	// Protected POST endpoint
	app.Post("/submit", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "POST success, CSRF token valid!",
		})
	})
	port := "8083"

	log.Fatal(app.Listen(":" + port))
}
