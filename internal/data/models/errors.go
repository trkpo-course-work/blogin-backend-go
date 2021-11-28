package models

import "errors"

var ErrNoRecord = errors.New("no record")
var ErrAlreadyExists = errors.New("entity already exists")
