package models

import "errors"

var ErrNoRecord = errors.New("no record")
var ErrAllreadyExists = errors.New("entity already exists")
var ErrNoReferenece = errors.New("invalid foreign key reference")
