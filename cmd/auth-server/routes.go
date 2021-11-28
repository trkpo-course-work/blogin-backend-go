package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (app *application) route() http.Handler {
	middleware.DefaultLogger = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app.logger.Debugw(r.URL.RequestURI(),
				"addr", r.RemoteAddr,
				"protocol", r.Proto,
				"method", r.Method,
			)
			next.ServeHTTP(w, r)
		})
	}

	r := chi.NewMux()

	r.Use(middleware.Logger, middleware.Recoverer, middleware.StripSlashes)
	r.NotFound(app.notFoundResponse)
	r.MethodNotAllowed(app.methodNotAllowedResponse)

	r.Route("/api/v1/auth", func(r chi.Router) {
		//	r.Post("/signup", app.signupUserHandler)
		r.Post("/login", app.loginUserHandler)
		r.Post("/refresh", app.refreshTokenHandler)
		r.Post("/logout", app.logoutUserHandler)

		r.Post("/request_confirmation", app.requestConfirmationHandler)
		r.Post("/confirm", app.confirmHandler)

		r.Post("/request_reset", app.requestResetHandler)
		r.Post("/check_reset_code", app.checkResetHandler)
		r.Post("/reset", app.resetHandler)
	})

	return r
}
