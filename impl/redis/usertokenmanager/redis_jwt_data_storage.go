package usertokenmanager

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sbasestarter/bizuserlib/bizuserinters/usertokenmanager"
	"github.com/sgostarter/i/l"
)

func NewRedisJWTDataStorage(redisCli *redis.Client, logger l.Wrapper) usertokenmanager.JWTDataStorage {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if redisCli == nil {
		logger.Error("no redis client")

		return nil
	}

	return &jwtDataStorageImpl{
		redisCli: redisCli,
		logger:   logger.WithFields(l.StringField(l.ClsKey, "jwtDataStorageImpl")),
	}
}

type jwtDataStorageImpl struct {
	redisCli *redis.Client
	logger   l.Wrapper
}

func (impl *jwtDataStorageImpl) Record(ctx context.Context, key string, expiration time.Duration) error {
	return impl.redisCli.Set(ctx, key, time.Now(), expiration).Err()
}

func (impl *jwtDataStorageImpl) Exists(ctx context.Context, key string) (t bool, err error) {
	n, err := impl.redisCli.Exists(ctx, key).Result()
	if err != nil {
		return
	}

	t = n > 0

	return
}
