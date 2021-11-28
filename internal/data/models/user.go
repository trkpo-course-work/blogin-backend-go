package models

type User struct {
	ID           int64  `json:"-" db:"id"`
	FullName     string `json:"full_name" db:"name"`
	Login        string `json:"login" db:"login"`
	Email        string `json:"email" db:"email"`
	PasswordHash string `json:"-" db:"password_hash"`
	Confirmed    bool   `json:"-" db:"confirmed"`
}
