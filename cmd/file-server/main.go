package main

import (
	"log"
	"net/http"
	"time"

	"github.com/SergeyKozhin/blogin-auth/internal/data/postgres"
	"github.com/SergeyKozhin/blogin-auth/internal/jwt"
	"github.com/xlab/closer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type application struct {
	config   *config
	logger   *zap.SugaredLogger
	jwts     *jwt.ManagerImplementation
	pictures *postgres.PicturesRepository
}

func main() {
	app, cleanup, err := initApp()
	if err != nil {
		log.Fatal("error initiating application", err)
	}
	closer.Bind(func() {
		log.Print("Stopping server")
		cleanup()
	})

	errLogger, err := zap.NewStdLogAt(app.logger.Desugar(), zap.ErrorLevel)
	if err != nil {
		app.logger.Fatalw("error initiating server logger", "err", err)
	}

	server := &http.Server{
		Addr:     ":" + app.config.Port,
		Handler:  app.route(),
		ErrorLog: errLogger,
	}

	app.logger.Infow("Started server", "port", app.config.Port)
	app.logger.Fatalw("server error", "err", server.ListenAndServe())
}

func newLogger(c *config) (*zap.SugaredLogger, func(), error) {
	var logger *zap.Logger
	var err error

	if c.Production {
		logger, err = zap.NewProduction()
	} else {
		conf := zap.NewDevelopmentConfig()
		conf.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		logger, err = conf.Build()
	}

	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		_ = logger.Sync()
	}

	return logger.Sugar(), cleanup, nil
}

func newPostgresConfig(c *config, logger *zap.SugaredLogger) *postgres.Config {
	return &postgres.Config{
		PostgresUrl: c.PostgresUrl,
		Logger:      logger,
	}
}

func newJwtConfig(c *config) *jwt.Config {
	return &jwt.Config{
		Secret:     c.Secret,
		Expiration: time.Duration(0),
	}
}
