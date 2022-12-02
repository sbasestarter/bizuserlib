package usertokenmanager

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sbasestarter/bizuserlib/bizuserinters/usertokenmanager"
)

func NewMemoryJWTDataStorage() usertokenmanager.JWTDataStorage {
	return &jwtDataStorageImpl{
		d: cache.New(time.Second, time.Second),
	}
}

type jwtDataStorageImpl struct {
	d *cache.Cache
}

func (impl *jwtDataStorageImpl) Record(ctx context.Context, key string, expiration time.Duration) error {
	impl.d.Set(key, time.Now(), expiration)

	return nil
}

func (impl *jwtDataStorageImpl) Exists(ctx context.Context, key string) (t bool, err error) {
	_, t = impl.d.Get(key)

	return
}
