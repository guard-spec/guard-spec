package main

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// The admin UI is a single-page app embedded from web/dist and served at /ui/.
// Paths without a file extension are client routes and get index.html.

// uiCSP allows only the UI's own files: no inline or remote scripts or
// styles, and API calls to this origin only.
const uiCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
	"frame-ancestors 'none'; form-action 'self'"

func uiHeaders(c *fiber.Ctx) {
	c.Set("Content-Security-Policy", uiCSP)
	c.Set(fiber.HeaderXFrameOptions, "DENY")
	c.Set(fiber.HeaderReferrerPolicy, "no-referrer")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
}

func mountUI(app *fiber.App, files fs.FS) {
	app.Get("/", func(c *fiber.Ctx) error { return c.Redirect("/ui/", fiber.StatusFound) })
	app.Get("/ui/*", serveUI(files)) // also matches /ui
}

func serveUI(files fs.FS) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Path() == "/ui" {
			return c.Redirect("/ui/", fiber.StatusFound)
		}
		uiHeaders(c)
		name := strings.TrimPrefix(path.Clean("/"+c.Params("*")), "/")
		if name == "" {
			name = "index.html"
		}
		data, err := readUIFile(files, name)
		if errors.Is(err, fs.ErrNotExist) && path.Ext(name) == "" {
			name = "index.html" // a client route
			data, err = readUIFile(files, name)
		}
		if errors.Is(err, fs.ErrNotExist) {
			return c.Status(fiber.StatusNotFound).SendString("not found")
		}
		if err != nil {
			return serverError(c, err)
		}
		ctype := mime.TypeByExtension(path.Ext(name))
		if ctype == "" {
			ctype = http.DetectContentType(data)
		}
		c.Set(fiber.HeaderContentType, ctype)
		// Vite puts content-hashed files under assets/; everything else may change.
		if strings.HasPrefix(name, "assets/") {
			c.Set(fiber.HeaderCacheControl, "public, max-age=31536000, immutable")
		} else {
			c.Set(fiber.HeaderCacheControl, "no-cache")
		}
		return c.Send(data)
	}
}

// readUIFile reads a regular file; a directory counts as missing.
func readUIFile(files fs.FS, name string) ([]byte, error) {
	info, err := fs.Stat(files, name)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fs.ErrNotExist
	}
	return fs.ReadFile(files, name)
}
