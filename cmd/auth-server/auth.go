package main

import (
	"errors"
	"net/http"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"golang.org/x/crypto/bcrypt"
)

var ErrorInvalidCredentials = errors.New("invalid credentials")

func (app *application) loginUserHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	user, err := app.users.GetByLogin(r.Context(), input.Login)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.unauthorizedResponse(w, r, ErrorInvalidCredentials)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	//if !user.Confirmed {
	//	app.forbiddenResponse(w, r, "account not confirmed")
	//	return
	//}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		app.unauthorizedResponse(w, r, ErrorInvalidCredentials)
		return
	}

	tokens, err := app.generateTokens(r.Context(), user.ID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if err := app.writeJSON(w, http.StatusOK, tokens, nil); err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

func (app *application) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		RefreshToken string `json:"refresh_token"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	id, err := app.refreshTokens.Get(r.Context(), input.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.unauthorizedResponse(w, r, errors.New("no such session"))
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	accessToken, err := app.jwts.CreateToken(id)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	newRefreshToken := ""
	for {
		newRefreshToken, err = app.generateRandomString(app.config.SessionTokenLength)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}

		if err := app.refreshTokens.Refresh(r.Context(), input.RefreshToken, newRefreshToken); err != nil {
			if errors.Is(err, models.ErrAllreadyExists) {
				continue
			}
			app.serverErrorResponse(w, r, err)
			return
		}

		break
	}

	response := &struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}

	if err := app.writeJSON(w, http.StatusOK, response, nil); err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

func (app *application) logoutUserHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		RefreshToken string `json:"refresh_token"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	if err := app.refreshTokens.Delete(r.Context(), input.RefreshToken); err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.unauthorizedResponse(w, r, errors.New("no such session"))
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}
