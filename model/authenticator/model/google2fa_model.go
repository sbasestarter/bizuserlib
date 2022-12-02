package model

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator/google2fa"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	google2fainters "github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/google2fa"
	"github.com/spf13/cast"
)

const (
	google2FASecretKey = "google2fa:secret"
)

func NewGoogle2FAModel(dbModel google2fainters.DBModel, tokenManagerModel authenticator.TokenManagerModel,
	cacheModel authenticator.CacheModel) google2fa.Model {
	if dbModel == nil {
		return nil
	}

	if tokenManagerModel == nil {
		return nil
	}

	if cacheModel == nil {
		return nil
	}

	return &google2FAModelImpl{
		dbModel:               dbModel,
		tokenManagerModel:     tokenManagerModel,
		cacheModel:            cacheModel,
		authenticatorIdentity: bizuserinters.AuthenticatorGoogle2FA,
	}
}

type google2FAModelImpl struct {
	dbModel               google2fainters.DBModel
	tokenManagerModel     authenticator.TokenManagerModel
	cacheModel            authenticator.CacheModel
	authenticatorIdentity bizuserinters.AuthenticatorIdentity
}

func (impl *google2FAModelImpl) CheckVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.CheckEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})
}

func (impl *google2FAModelImpl) CheckRegisterEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.CheckEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	})
}

func (impl *google2FAModelImpl) GetGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status) {
	return impl.dbModel.GetGoogle2FASecretKey(ctx, bizID)
}

func (impl *google2FAModelImpl) GetGoogle2FASetupUserInfo(ctx context.Context, bizID string) (name string, status bizuserinters.Status) {
	userInfo, status := impl.tokenManagerModel.GetCurrentUserInfo(ctx, bizID)
	if status.Code == bizuserinters.StatusCodeOk {
		name = userInfo.UserName
	}

	return
}

func (impl *google2FAModelImpl) CacheGoogle2FASecretKey(ctx context.Context, bizID, secretKey string) (status bizuserinters.Status) {
	return impl.cacheModel.Set(ctx, impl.cacheSecretKey(bizID), secretKey)
}

func (impl *google2FAModelImpl) GetCachedGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status) {
	i, status := impl.cacheModel.Get(ctx, impl.cacheSecretKey(bizID))
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	secretKey = cast.ToString(i)
	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *google2FAModelImpl) SetGoogle2FASecretKeyAndMarkRegisterEventCompleted(ctx context.Context, bizID string, secretKey string) (status bizuserinters.Status) {
	status = impl.tokenManagerModel.SetAuthenticatorData(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	}, map[string]interface{}{
		google2FASecretKey: secretKey,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	})

	return
}

func (impl *google2FAModelImpl) MarkVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})
}

//
//
//

func (impl *google2FAModelImpl) cacheSecretKey(bizID string) string {
	return bizID + ":" + "secretKey"
}
