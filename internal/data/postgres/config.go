package postgres

import (
	"go.uber.org/zap"
)

type Config struct {
	PostgresUrl string
	Logger      *zap.SugaredLogger
}
