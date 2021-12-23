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

	r.Route("/api/v1/pictures", func(r chi.Router) {
		r.Post("/", app.uploadPicture)
		r.With(app.pictureCtx).Route("/{pictureID}", func(r chi.Router) {
			r.Get("/", app.downloadPicture)
			r.Delete("/", app.deletePicture)
		})
	})

	return r
}
