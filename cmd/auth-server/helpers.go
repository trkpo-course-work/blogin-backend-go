package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
)

func (app *application) writeJSON(w http.ResponseWriter, status int, data interface{}, headers http.Header) error {
	js, err := json.Marshal(data)
	if err != nil {
		return err
	}
	js = append(js, '\n')

	for key, value := range headers {
		w.Header()[key] = value
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}

func (app *application) readJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	maxBytes := 1_048_576
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		var invalidUnmarshalError *json.InvalidUnmarshalError

		switch {
		case errors.As(err, &syntaxError):
			return fmt.Errorf("body contains badly-formed JSON (at character %d)", syntaxError.Offset)

		case errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("body contains badly-formed JSON")

		case errors.As(err, &unmarshalTypeError):
			if unmarshalTypeError.Field != "" {
				return fmt.Errorf("body contains incorrect JSON type for field %q", unmarshalTypeError.Field)
			}
			return fmt.Errorf("body contains incorrect JSON type (at character %d)", unmarshalTypeError.Offset)

		case errors.Is(err, io.EOF):
			return errors.New("body must not be empty")

		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			return fmt.Errorf("body contains unknown key %s", fieldName)

		case err.Error() == "http: request body too large":
			return fmt.Errorf("body must not be larger than %d bytes", maxBytes)

		case errors.As(err, &invalidUnmarshalError):
			panic(err)

		default:
			return err
		}
	}

	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("body must only contain a single JSON value")
	}

	return nil
}

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var limit = big.NewInt(int64(len(alphabet)))

func (app *application) generateRandomString(n int) (string, error) {
	b := make([]byte, n)

	for i := range b {
		num, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[num.Int64()]
	}

	return string(b), nil
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (app *application) generateTokens(ctx context.Context, id int64) (*tokens, error) {
	accessToken, err := app.jwts.CreateToken(id)
	if err != nil {
		return nil, err
	}

	refreshToken := ""
	for {
		refreshToken, err = app.generateRandomString(app.config.SessionTokenLength)
		if err != nil {
			return nil, err
		}

		if err := app.refreshTokens.Add(ctx, refreshToken, id); err != nil {
			if errors.Is(err, models.ErrAlreadyExists) {
				continue
			}
			return nil, err
		}

		break
	}

	return &tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
