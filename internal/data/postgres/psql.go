package postgres

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
)

func NewPsqlPool(c *Config) (*pgxpool.Pool, func(), error) {
	pool, err := pgxpool.Connect(context.Background(), c.PostgresUrl)
	if err != nil {
		return nil, nil, err
	}

	return pool, pool.Close, nil
}
