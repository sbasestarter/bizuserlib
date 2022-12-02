package authenticator

import (
	"context"
	"sync"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
)

func NewMemoryCacheModel() authenticator.CacheModel {
	return &memoryCacheModelImpl{}
}

type memoryCacheModelImpl struct {
	m sync.Map
}

func (impl *memoryCacheModelImpl) Set(ctx context.Context, key string, val interface{}) (status bizuserinters.Status) {
	impl.m.Store(key, val)

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryCacheModelImpl) Get(ctx context.Context, key string) (val interface{}, status bizuserinters.Status) {
	val, ok := impl.m.Load(key)
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError
	} else {
		status.Code = bizuserinters.StatusCodeOk
	}

	return
}

func (impl *memoryCacheModelImpl) Del(ctx context.Context, key string) (status bizuserinters.Status) {
	impl.m.Delete(key)

	status.Code = bizuserinters.StatusCodeOk

	return
}
