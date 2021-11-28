//go:build wireinject
// +build wireinject

package main

import (
	"github.com/SergeyKozhin/blogin-auth/internal/data/postgres"
	"github.com/SergeyKozhin/blogin-auth/internal/data/redis"
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
		newJwtConfig,
		jwt.NewManger,
		newRedisConfig,
		redis.NewRedisPool,
		redis.NewRefreshTokenRepository,
		//redis.NewCodesRepository,
		//newMailConfig,
		//email.NewMailSender,
		//newSubscriptionMangerConfig,
		//wire.Bind(new(subscription.SubscriptionRepository), new(*postgres.SubscriptionRepository)),
		wire.Struct(new(application), "*"),
	)

	return nil, nil, nil
}
