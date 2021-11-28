package redis

import (
	"context"

	"github.com/gomodule/redigo/redis"
	"go.uber.org/zap"
)

func NewRedisPool(c *Config, logger *zap.SugaredLogger) (*redis.Pool, func()) {
	pool := &redis.Pool{
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", c.RedisUrl)
		},
		DialContext: func(ctx context.Context) (redis.Conn, error) {
			return redis.DialContext(ctx, "tcp", c.RedisUrl)
		},
	}
	return pool, func() {
		if err := pool.Close(); err != nil {
			logger.Errorw("Failed closing redis pool", "err", err)
		}
	}
}
