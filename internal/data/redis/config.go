package redis

import (
	"time"
)

type Config struct {
	RedisUrl             string
	SessionTTl           time.Duration
	SessionCleanupPeriod time.Duration
	SessionWindowPeriod  time.Duration
	CodeTTL              time.Duration
}
