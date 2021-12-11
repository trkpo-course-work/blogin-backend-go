package main

import (
	"github.com/caarlos0/env"
)

type config struct {
	Production   bool   `env:"PRODUCTION" envDefault:"false"`
	Port         string `env:"PORT" envDefault:"80"`
	PostgresUrl  string `env:"POSTGRES_URL,required"`
	Secret       string `env:"SECRET,required"`
	PicturesPath string `env:"PICTURES_PATH" envDefault:"/pictures"`
	MaxFileSize  int64  `env:"MAX_FILE_SIZE" envDefault:"5242880"`
}

func getConfig() (*config, error) {
	c := &config{}
	if err := env.Parse(c); err != nil {
		return nil, err
	}
	return c, nil
}
