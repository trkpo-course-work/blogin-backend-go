package models

import (
	"github.com/SergeyKozhin/blogin-auth/internal/validator"
)

type User struct {
	ID           int64  `json:"-" db:"id"`
	FullName     string `json:"full_name" db:"name"`
	Login        string `json:"login" db:"login"`
	Email        string `json:"email" db:"email"`
	PasswordHash string `json:"-" db:"password_hash"`
	Confirmed    bool   `json:"-" db:"confirmed"`
}

func ValidateUser(v *validator.Validator, user *User) {
	v.Check(len(user.FullName) != 0, "full_name", "full name must be provided")
	v.Check(len(user.Login) != 0, "login", "login name must be provided")
	v.Check(validator.Matches(user.Email, validator.EmailRX), "email", "valid email must be provided")
}
