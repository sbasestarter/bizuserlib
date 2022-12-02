package authenticator

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	"github.com/sgostarter/i/l"
)

func NewRedisCacheModel(redisCli *redis.Client, prefixKey string, expiration time.Duration, logger l.Wrapper) authenticator.CacheModel {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if redisCli == nil {
		logger.Errorf("no redis client")

		return nil
	}

	return &cacheModelImpl{
		redisCli:   redisCli,
		prefixKey:  prefixKey,
		expiration: expiration,
		logger:     logger.WithFields(l.StringField(l.ClsKey, "cacheModelImpl")),
	}
}

type cacheModelImpl struct {
	redisCli   *redis.Client
	prefixKey  string
	expiration time.Duration
	logger     l.Wrapper
}

func (impl *cacheModelImpl) Set(ctx context.Context, key string, val interface{}) bizuserinters.Status {
	err := impl.redisCli.Set(ctx, impl.redisKey(key), val, impl.expiration).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *cacheModelImpl) Get(ctx context.Context, key string) (val interface{}, status bizuserinters.Status) {
	s, err := impl.redisCli.Get(ctx, impl.redisKey(key)).Result()
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	val = s
	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *cacheModelImpl) Del(ctx context.Context, key string) bizuserinters.Status {
	err := impl.redisCli.Del(ctx, impl.redisKey(key)).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

//
//
//

func (impl *cacheModelImpl) redisKey(key string) string {
	return impl.prefixKey + key
}
