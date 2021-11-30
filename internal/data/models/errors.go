package models

import "errors"

var ErrNoRecord = errors.New("no record")
var ErrAlreadyExists = errors.New("entity already exists")

type ErrUserAlreadyExists struct {
	Column string
}

func (e *ErrUserAlreadyExists) Error() string {
	return e.Column + " is already in use"
}
