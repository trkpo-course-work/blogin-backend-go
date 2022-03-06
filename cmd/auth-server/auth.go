package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"github.com/SergeyKozhin/blogin-auth/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

var ErrorInvalidCredentials = errors.New("invalid credentials")

func (app *application) signupUserHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		FullName string `json:"full_name"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	v := validator.New()

	v.Check(len(input.FullName) != 0, "full_name", "full name name must be provided")
	v.Check(len(input.Login) != 0, "login", "login name must be provided")
	v.Check(validator.Matches(input.Email, validator.EmailRX), "email", "valid email must be provided")
	v.Check(len(input.Password) != 0, "password", "password must be provided")

	if !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	user := &models.User{
		FullName:     input.FullName,
		Login:        input.Login,
		Email:        strings.ToLower(input.Email),
		PasswordHash: string(hash),
	}

	if err := app.users.Add(r.Context(), user); err != nil {
		var alreadyExistErr *models.ErrUserAlreadyExists
		switch {
		case errors.As(err, &alreadyExistErr):
			app.userAlreadyExistsResponse(w, r, alreadyExistErr.Column)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
}

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

	if !user.Confirmed {
		app.forbiddenResponse(w, r, "user not confirmed")
		return
	}

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
			if errors.Is(err, models.ErrAlreadyExists) {
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

func (app *application) requestConfirmationHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		Login string `json:"login"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	user, err := app.users.GetByLogin(r.Context(), input.Login)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	if user.Confirmed {
		app.forbiddenResponse(w, r, "user already confirmed")
		return
	}

	code := ""
	for {
		code, err = app.generateRandomString(app.config.CodeLength)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}

		if err := app.codes.Add(r.Context(), code, user.ID); err != nil {
			if errors.Is(err, models.ErrAlreadyExists) {
				continue
			}
			app.serverErrorResponse(w, r, err)
			return
		}

		break
	}

	if err := app.mail.SendConfirmationCode(user.Email, code); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (app *application) confirmHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		Login string `json:"login"`
		Code  string `json:"code"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	id, err := app.codes.Get(r.Context(), input.Code)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	user, err := app.users.GetByID(r.Context(), id)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if user.Login != input.Login {
		app.notFoundResponse(w, r)
		return
	}

	user.Confirmed = true
	if err := app.users.Update(r.Context(), user); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if err := app.codes.Delete(r.Context(), input.Code); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (app *application) requestResetHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		Email string `json:"email"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	user, err := app.users.GetByEmail(r.Context(), input.Email)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	if !user.Confirmed {
		app.forbiddenResponse(w, r, "user not confirmed")
		return
	}

	code := ""
	for {
		code, err = app.generateRandomString(app.config.CodeLength)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}

		if err := app.codes.Add(r.Context(), code, user.ID); err != nil {
			if errors.Is(err, models.ErrAlreadyExists) {
				continue
			}
			app.serverErrorResponse(w, r, err)
			return
		}

		break
	}

	if err := app.mail.SendResetCode(input.Email, code); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (app *application) checkResetHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	id, err := app.codes.Get(r.Context(), input.Code)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	user, err := app.users.GetByID(r.Context(), id)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if user.Email != input.Email {
		app.notFoundResponse(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (app *application) resetHandler(w http.ResponseWriter, r *http.Request) {
	input := &struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}{}

	if err := app.readJSON(w, r, input); err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	v := validator.New()
	v.Check(len(input.Password) != 0, "password", "password must be provided")

	if !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	id, err := app.codes.Get(r.Context(), input.Code)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrNoRecord):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	user, err := app.users.GetByID(r.Context(), id)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if user.Email != input.Email {
		app.notFoundResponse(w, r)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	user.PasswordHash = string(hash)
	if err := app.users.Update(r.Context(), user); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if err := app.codes.Delete(r.Context(), input.Code); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
