//go:build wireinject
// +build wireinject

package main

import (
	"github.com/google/wire"
)

func initApp() (*application, func(), error) {
	wire.Build(
		getConfig,
		newLogger,
		//newPostgresConfig,
		//postgres.NewPsqlPool,
		//wire.Struct(new(postgres.UserRepository), "*"),
		//wire.Struct(new(postgres.StudentsRepository), "*"),
		//wire.Struct(new(postgres.FilesRepository), "*"),
		//wire.Struct(new(postgres.ParentsRepository), "*"),
		//wire.Struct(new(postgres.FinancesRepository), "*"),
		//wire.Struct(new(postgres.SubscriptionRepository), "*"),
		//postgres.NewClassesRepository,
		//newJwtConfig,
		//jwt.NewManger,
		//newRedisConfig,
		//redis.NewRedisPool,
		//redis.NewRefreshTokenRepository,
		//redis.NewCodesRepository,
		//newMailConfig,
		//email.NewMailSender,
		//newSubscriptionMangerConfig,
		//wire.Bind(new(subscription.SubscriptionRepository), new(*postgres.SubscriptionRepository)),
		//subscription.NewManager,
		//newOAuthConfig,
		//oauth.NewManager,
		wire.Struct(new(application), "*"),
	)

	return nil, nil, nil
}
