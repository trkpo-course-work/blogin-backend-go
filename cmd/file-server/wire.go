//go:build wireinject
// +build wireinject

package main

import (
	"github.com/SergeyKozhin/blogin-auth/internal/data/postgres"
	"github.com/SergeyKozhin/blogin-auth/internal/jwt"
	"github.com/google/wire"
)

func initApp() (*application, func(), error) {
	wire.Build(
		getConfig,
		newLogger,
		newPostgresConfig,
		postgres.NewPsqlPool,
		wire.Struct(new(postgres.PicturesRepository), "*"),
		newJwtConfig,
		jwt.NewManger,
		wire.Struct(new(application), "*"),
	)

	return nil, nil, nil
}
