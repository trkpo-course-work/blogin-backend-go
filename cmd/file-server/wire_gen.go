// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/SergeyKozhin/blogin-auth/internal/data/postgres"
	"github.com/SergeyKozhin/blogin-auth/internal/jwt"
)

// Injectors from wire.go:

func initApp() (*application, func(), error) {
	mainConfig, err := getConfig()
	if err != nil {
		return nil, nil, err
	}
	sugaredLogger, cleanup, err := newLogger(mainConfig)
	if err != nil {
		return nil, nil, err
	}
	jwtConfig := newJwtConfig(mainConfig)
	managerImplementation := jwt.NewManger(jwtConfig)
	postgresConfig := newPostgresConfig(mainConfig, sugaredLogger)
	pool, cleanup2, err := postgres.NewPsqlPool(postgresConfig)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	picturesRepository := &postgres.PicturesRepository{
		DB: pool,
	}
	mainApplication := &application{
		config:   mainConfig,
		logger:   sugaredLogger,
		jwts:     managerImplementation,
		pictures: picturesRepository,
	}
	return mainApplication, func() {
		cleanup2()
		cleanup()
	}, nil
}
