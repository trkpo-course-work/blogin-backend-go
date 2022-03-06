package main

import (
	"fmt"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"golang.org/x/crypto/bcrypt"
)

type userWithPass struct {
	user     *models.User
	password string
}

func IsUserWithPassword(user *models.User, password string) *userWithPass {
	return &userWithPass{
		user:     user,
		password: password,
	}
}

func (u *userWithPass) Matches(in interface{}) bool {
	inUser, ok := in.(*models.User)
	if !ok {
		return false
	}

	return u.user.ID == inUser.ID &&
		u.user.FullName == inUser.FullName &&
		u.user.Email == inUser.Email &&
		u.user.Login == inUser.Login &&
		u.user.Confirmed == inUser.Confirmed &&
		bcrypt.CompareHashAndPassword([]byte(inUser.PasswordHash), []byte(u.password)) == nil
}

func (u *userWithPass) String() string {
	return fmt.Sprintf("is equal to user %v with password %q", u.user, u.password)
}
