package model

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator/userpass"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	userpassmodel "github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/userpass"
)

const (
	userPassUserID   = "user_pass:user_id"
	userPassUsername = "user_pass:user_name" // nolint: gosec
	userPassPassword = "user_pass:password"
)

func NewUserPassModel(dbModel userpassmodel.DBModel, tokenManagerModel authenticator.TokenManagerModel) userpass.Model {
	if dbModel == nil || tokenManagerModel == nil {
		return nil
	}

	return &userPassModelImpl{
		dbModel:               dbModel,
		tokenManagerModel:     tokenManagerModel,
		authenticatorIdentity: bizuserinters.AuthenticatorUserPass,
	}
}

type userPassModelImpl struct {
	dbModel               userpassmodel.DBModel
	tokenManagerModel     authenticator.TokenManagerModel
	authenticatorIdentity bizuserinters.AuthenticatorIdentity
}

func (impl *userPassModelImpl) GetUserPassInfo(ctx context.Context, bizID string) (userID uint64, userName, password string, status bizuserinters.Status) {
	userID, userName, password, status = impl.dbModel.GetUserPassInfo(ctx, bizID)

	return
}

func (impl *userPassModelImpl) MarkVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})
}

func (impl *userPassModelImpl) SetNewPasswordAndMarkChangeEventCompleted(ctx context.Context, bizID string, password string) (status bizuserinters.Status) {
	status = impl.tokenManagerModel.SetAuthenticatorData(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	}, map[string]interface{}{
		userPassPassword: password,
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

func (impl *userPassModelImpl) GetUserPassInfoByUserName(ctx context.Context, bizID string, userName string) (userID uint64, password string, status bizuserinters.Status) {
	return impl.dbModel.GetUserPassInfoByUserName(ctx, bizID, userName)
}

func (impl *userPassModelImpl) CheckVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.CheckEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})
}

func (impl *userPassModelImpl) CheckRegisterEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.CheckEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	})
}

func (impl *userPassModelImpl) SetVerifiedUserInfoAndMarkVerifyEventCompleted(ctx context.Context, bizID string, userID uint64, userName string) (status bizuserinters.Status) {
	status = impl.tokenManagerModel.SetAuthenticatorData(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	}, map[string]interface{}{
		userPassUserID:   userID,
		userPassUsername: userName,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})

	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.SetCurrentUserInfo(ctx, bizID, &bizuserinters.UserIdentity{
		ID:       userID,
		UserName: userName,
	})

	return
}

func (impl *userPassModelImpl) AddUserAndMarkRegisterEventCompleted(ctx context.Context, bizID string, userName string, password string) (status bizuserinters.Status) {
	_, status = impl.tokenManagerModel.GetCurrentUserInfo(ctx, bizID)
	if status.Code == bizuserinters.StatusCodeOk {
		status.Code = bizuserinters.StatusCodeDupError

		return
	}

	status = impl.tokenManagerModel.SetAuthenticatorData(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	}, map[string]interface{}{
		userPassUsername: userName,
		userPassPassword: password,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.RegisterEvent,
	})

	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.SetCurrentUserInfo(ctx, bizID, &bizuserinters.UserIdentity{
		ID:       0,
		UserName: userName,
	})

	return
}
