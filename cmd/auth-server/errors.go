package main

import (
	"fmt"
	"net/http"
)

func (app *application) logError(r *http.Request, err error) {
	app.logger.Errorw("server error", "error", err)
}

func (app *application) errorResponse(w http.ResponseWriter, r *http.Request, status int, mesaage interface{}) {
	data := map[string]interface{}{"error": mesaage}

	if err := app.writeJSON(w, status, data, nil); err != nil {
		app.logError(r, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (app *application) serverErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.logError(r, err)

	message := "the server encountered a problem and could not process your request"
	app.errorResponse(w, r, http.StatusInternalServerError, message)
}

func (app *application) clientErrorResponse(w http.ResponseWriter, r *http.Request, status int, message interface{}) {
	app.logger.Debugw("client error", "err", message)
	app.errorResponse(w, r, status, message)
}

func (app *application) notFoundResponse(w http.ResponseWriter, r *http.Request) {
	message := "the requested resource could not be found"
	app.clientErrorResponse(w, r, http.StatusNotFound, message)
}

func (app *application) methodNotAllowedResponse(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("the %s method is not supported for this resource", r.Method)
	app.clientErrorResponse(w, r, http.StatusMethodNotAllowed, message)
}

func (app *application) badRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.clientErrorResponse(w, r, http.StatusBadRequest, err.Error())
}

func (app *application) failedValidationResponse(w http.ResponseWriter, r *http.Request, errors map[string]string) {
	app.clientErrorResponse(w, r, http.StatusUnprocessableEntity, errors)
}

func (app *application) unauthorizedResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.clientErrorResponse(w, r, http.StatusUnauthorized, err.Error())
}

func (app *application) userAllreadyExistsResponse(w http.ResponseWriter, r *http.Request) {
	app.clientErrorResponse(w, r, http.StatusConflict, "user with provided email already exists")
}

func (app *application) subscriptionAlreadyActiveResponse(w http.ResponseWriter, r *http.Request) {
	app.clientErrorResponse(w, r, http.StatusConflict, "subscription already active")
}

func (app *application) subscriptionAlreadyActiveOnAnotherAccount(w http.ResponseWriter, r *http.Request) {
	app.clientErrorResponse(w, r, http.StatusConflict, "subscription already active on another account")
}

func (app *application) fileTooBigResponse(w http.ResponseWriter, r *http.Request) {
	app.clientErrorResponse(w, r, http.StatusConflict, "file is too big")
}

func (app *application) noPasswordSetResponse(w http.ResponseWriter, r *http.Request) {
	app.clientErrorResponse(w, r, http.StatusConflict, "no password set")
}

func (app *application) forbiddenResponse(w http.ResponseWriter, r *http.Request, messsage string) {
	app.clientErrorResponse(w, r, http.StatusForbidden, messsage)
}

func (app *application) subscriptionInactive(w http.ResponseWriter, r *http.Request) {
	app.clientErrorResponse(w, r, http.StatusPaymentRequired, "subscription inactive")
}
