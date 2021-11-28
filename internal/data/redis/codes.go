package redis

import (
	"context"
	"errors"
	"time"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"github.com/gomodule/redigo/redis"
)

type CodesRepository struct {
	Pool    *redis.Pool
	CodeTTL time.Duration
}

func NewCodesRepository(pool *redis.Pool, c *Config) *CodesRepository {
	return &CodesRepository{
		Pool:    pool,
		CodeTTL: c.CodeTTL,
	}
}

func (cr *CodesRepository) Add(ctx context.Context, code string, id int64) error {
	conn, err := cr.Pool.GetContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	exists, err := redis.Bool(conn.Do("EXISTS", "code:"+code))
	if err != nil {
		return err
	}
	if exists {
		return models.ErrAlreadyExists
	}

	return conn.Send("SET", "code:"+code, id, "EX", int(cr.CodeTTL.Seconds()))
}

func (cr *CodesRepository) Get(ctx context.Context, code string) (int64, error) {
	conn, err := cr.Pool.GetContext(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	id, err := redis.Int64(conn.Do("GET", "code:"+code))
	if err != nil {
		if errors.Is(err, redis.ErrNil) {
			return 0, models.ErrNoRecord
		}
		return 0, err
	}

	return id, nil
}

func (cr *CodesRepository) Delete(ctx context.Context, code string) error {
	conn, err := cr.Pool.GetContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Send("DEL", "code:"+code)
}
