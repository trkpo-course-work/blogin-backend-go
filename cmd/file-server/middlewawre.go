package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"github.com/go-chi/chi/v5"

	"github.com/SergeyKozhin/blogin-auth/internal/jwt"
)

type contextKey string

const (
	contextKeyID      = contextKey("id")
	contextKeyPicture = contextKey("address")
)

var (
	ErrCantRetrieveEntity = errors.New("can't retrieve entity")
)

func (app *application) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			app.unauthorizedResponse(w, r, errors.New("no token provided"))
			return
		}

		token = strings.TrimPrefix(token, "Bearer ")

		id, err := app.jwts.GetIdFromToken(token)
		if err != nil {
			invalidTokenErr := &jwt.InvalidTokenError{}
			switch {
			case errors.As(err, &invalidTokenErr):
				app.unauthorizedResponse(w, r, invalidTokenErr)
			default:
				app.serverErrorResponse(w, r, err)
			}
			return
		}

		idContext := context.WithValue(r.Context(), contextKeyID, id)
		next.ServeHTTP(w, r.WithContext(idContext))
	})
}

func (app *application) pictureCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(chi.URLParam(r, "pictureID"), 10, 64)
		if err != nil {
			app.notFoundResponse(w, r)
			return
		}

		picture, err := app.pictures.GetByID(r.Context(), id)
		if err != nil {
			switch {
			case errors.Is(err, models.ErrNoRecord):
				app.notFoundResponse(w, r)
			default:
				app.serverErrorResponse(w, r, err)
			}
			return
		}

		studentCtx := context.WithValue(r.Context(), contextKeyPicture, picture)
		next.ServeHTTP(w, r.WithContext(studentCtx))
	})
}
