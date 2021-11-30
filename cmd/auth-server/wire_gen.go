// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/SergeyKozhin/blogin-auth/internal/data/postgres"
	"github.com/SergeyKozhin/blogin-auth/internal/data/redis"
	"github.com/SergeyKozhin/blogin-auth/internal/email"
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
	manager := jwt.NewManger(jwtConfig)
	redisConfig := newRedisConfig(mainConfig)
	pool, cleanup2 := redis.NewRedisPool(redisConfig, sugaredLogger)
	refreshTokenRepository, cleanup3 := redis.NewRefreshTokenRepository(pool, redisConfig, sugaredLogger)
	postgresConfig := newPostgresConfig(mainConfig, sugaredLogger)
	pgxpoolPool, cleanup4, err := postgres.NewPsqlPool(postgresConfig)
	if err != nil {
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	userRepository := &postgres.UserRepository{
		DB: pgxpoolPool,
	}
	codesRepository := redis.NewCodesRepository(pool, redisConfig)
	emailConfig := newMailConfig(mainConfig)
	mailSender := email.NewMailSender(emailConfig)
	mainApplication := &application{
		config:        mainConfig,
		logger:        sugaredLogger,
		jwts:          manager,
		refreshTokens: refreshTokenRepository,
		users:         userRepository,
		codes:         codesRepository,
		mail:          mailSender,
	}
	return mainApplication, func() {
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
	}, nil
}