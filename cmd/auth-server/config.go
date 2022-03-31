package main

import (
	"time"

	"github.com/caarlos0/env"
)

type config struct {
	Production           bool          `env:"PRODUCTION" envDefault:"false"`
	Port                 string        `env:"PORT" envDefault:"80"`
	PostgresUrl          string        `env:"POSTGRES_URL,required"`
	RedisUrl             string        `env:"REDIS_URL" envDefault:"redis:6379"`
	JwtTTL               time.Duration `env:"TOKEN_TTL" envDefault:"20m"`
	Secret               string        `env:"SECRET,required"`
	SessionTTl           time.Duration `env:"SESSION_TTL" envDefault:"168h"`
	SessionCleanupPeriod time.Duration `env:"SESSION_CLEANUP_PERIOD" envDefault:"60s"`
	SessionWindowPeriod  time.Duration `env:"SESSION_WINDOW_PERIOD" envDefault:"60s"`
	SessionTokenLength   int           `env:"SESSION_TOKEN_LENGTH" envDefault:"32"`
	CodeTTL              time.Duration `env:"CODE_TTL" envDefault:"24h"`
	CodeLength           int           `env:"CODE_LENGTH" envDefault:"5"`
	EmailServer          string        `env:"EMAIL_SERVER" envDefault:"smtp.gmail.com"`
	EmailPort            string        `env:"EMAIL_PORT" envDefault:"587"`
	EmailLogin           string        `env:"EMAIL_LOGIN" envDefault:"blogin.app.noreply@gmail.com"`
	EmailPass            string        `env:"EMAIL_PASS,required"`
	TestAccountSuffix    string        `env:"TEST_ACCOUNT" envDefault:"@test.com"`
	TestAccountCode      string        `env:"TEST_ACCOUNT_CODE" envDefault:"TEST1"`
}

func getConfig() (*config, error) {
	c := &config{}
	if err := env.Parse(c); err != nil {
		return nil, err
	}
	return c, nil
}
