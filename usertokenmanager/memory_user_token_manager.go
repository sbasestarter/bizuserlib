package usertokenmanager

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"
	uuid "github.com/satori/go.uuid"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/spf13/cast"
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

	userInfo.StartAt = time.Now()

	if userInfo.Expiration <= 0 {
		userInfo.Expiration = cache.NoExpiration
	}

	impl.dataCache.Set(token, &userInfo, userInfo.Expiration)

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

	userInfo.StartAt = time.Now()

	impl.dataCache.Set(newToken, userInfo, userInfo.Expiration)
	impl.dataCache.Set(token, userInfo, time.Minute)

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryUserTokenManagerImpl) GenSSOToken(ctx context.Context, parentToken string, expiration time.Duration) (token string, status bizuserinters.Status) {
	_, status = impl.ExplainToken(ctx, parentToken)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	token = uuid.NewV4().String()

	impl.dataCache.Set(token, parentToken, expiration)

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryUserTokenManagerImpl) ExplainSSOToken(ctx context.Context, token string) (userInfo *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	i, ok := impl.dataCache.Get(token)
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	parentToken, err := cast.ToStringE(i)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)

		return
	}

	userInfo, status = impl.ExplainToken(ctx, parentToken)

	return
}
