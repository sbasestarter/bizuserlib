package usertokenmanager

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"
	uuid "github.com/satori/go.uuid"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func NewMemoryUserTokenManager() bizuserinters.UserTokenManager {
	return &memoryUserTokenManagerImpl{
		dataCache: cache.New(time.Hour, time.Hour),
	}
}

type memoryUserTokenManagerImpl struct {
	dataCache *cache.Cache
}

func (impl *memoryUserTokenManagerImpl) GenToken(_ context.Context, ui *bizuserinters.UserTokenInfo) (token string, status bizuserinters.Status) {
	token = uuid.NewV4().String()

	userInfo := *ui

	if userInfo.Age <= 0 {
		userInfo.Age = cache.NoExpiration
	}

	impl.dataCache.Set(token, &userInfo, userInfo.Age)

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryUserTokenManagerImpl) DeleteToken(_ context.Context, token string) (status bizuserinters.Status) {
	impl.dataCache.Delete(token)

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryUserTokenManagerImpl) ExplainToken(ctx context.Context, token string) (userInfo *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	i, ok := impl.dataCache.Get(token)
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	ui, ok := i.(*bizuserinters.UserTokenInfo)
	if !ok {
		status.Code = bizuserinters.StatusCodeInternalError

		return
	}

	userInfoObj := *ui
	userInfo = &userInfoObj

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryUserTokenManagerImpl) RenewToken(ctx context.Context, token string) (newToken string, userInfo *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	userInfo, status = impl.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	newToken = uuid.NewV4().String()

	impl.dataCache.Set(newToken, userInfo, userInfo.Age)
	impl.dataCache.Set(token, userInfo, time.Minute)

	status.Code = bizuserinters.StatusCodeOk

	return
}