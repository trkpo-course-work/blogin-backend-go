package jwt

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type InvalidTokenError struct {
	message string
}

func (e *InvalidTokenError) Error() string {
	return e.message
}

var (
	ErrInvalidToken   = &InvalidTokenError{"invalid token"}
	ErrExpiredToken   = &InvalidTokenError{"expired token"}
	ErrInvalidSubject = &InvalidTokenError{"invalid subject"}
)

type Config struct {
	Secret     string
	Expiration time.Duration
}

type Manager interface {
	CreateToken(id int64) (string, error)
	GetIdFromToken(token string) (int64, error)
}

type ManagerImplementation struct {
	Secret     string
	Expiration time.Duration
}

func NewManger(c *Config) *ManagerImplementation {
	return &ManagerImplementation{
		Secret:     c.Secret,
		Expiration: c.Expiration,
	}
}

func (m *ManagerImplementation) CreateToken(id int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		IssuedAt:  &jwt.NumericDate{Time: time.Now()},
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(m.Expiration)},
		Subject:   strconv.FormatInt(id, 10),
	})

	return token.SignedString([]byte(m.Secret))
}

func (m *ManagerImplementation) GetIdFromToken(token string) (int64, error) {
	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.Secret), nil
	})
	if err != nil {
		var jwtErr *jwt.ValidationError
		if errors.As(err, &jwtErr); jwtErr.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return 0, ErrExpiredToken
		}
		return 0, ErrInvalidToken
	}

	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return 0, ErrInvalidToken
	}

	id, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, ErrInvalidSubject
	}

	return id, nil
}
