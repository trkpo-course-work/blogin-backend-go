//go:build wireinject
// +build wireinject

package main

import (
	"github.com/SergeyKozhin/blogin-auth/internal/data"
	"github.com/SergeyKozhin/blogin-auth/internal/data/postgres"
	"github.com/SergeyKozhin/blogin-auth/internal/data/redis"
	"github.com/SergeyKozhin/blogin-auth/internal/email"
	"github.com/SergeyKozhin/blogin-auth/internal/jwt"
	"github.com/google/wire"
)

func initApp() (*application, func(), error) {
	wire.Build(
		getConfig,
		newLogger,
		newPostgresConfig,
		postgres.NewPsqlPool,
		wire.Struct(new(postgres.UserRepository), "*"),
		wire.Bind(new(data.UserRepository), new(*postgres.UserRepository)),
		newJwtConfig,
		jwt.NewManger,
		wire.Bind(new(jwt.Manager), new(*jwt.ManagerImplementation)),
		newRedisConfig,
		redis.NewRedisPool,
		redis.NewRefreshTokenRepository,
		wire.Bind(new(data.RefreshTokenRepository), new(*redis.RefreshTokenRepository)),
		redis.NewCodesRepository,
		wire.Bind(new(data.CodesRepository), new(*redis.CodesRepository)),
		newMailConfig,
		email.NewMailSender,
		wire.Bind(new(email.MailSender), new(*email.MailSenderClient)),
		newRandSource,
		wire.Struct(new(application), "*"),
	)

	return nil, nil, nil
}
