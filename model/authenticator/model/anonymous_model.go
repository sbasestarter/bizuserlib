package model

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator/anonymous"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
)

func NewAnonymousModel(tokenManagerModel authenticator.TokenManagerModel) anonymous.Model {
	if tokenManagerModel == nil {
		return nil
	}

	return &anonymousModelImpl{
		Base: Base{
			TokenManager: tokenManagerModel,
		},
		tokenManagerModel:     tokenManagerModel,
		authenticatorIdentity: bizuserinters.AuthenticatorAnonymous,
	}
}

type anonymousModelImpl struct {
	Base
	tokenManagerModel     authenticator.TokenManagerModel
	authenticatorIdentity bizuserinters.AuthenticatorIdentity
}

func (impl *anonymousModelImpl) CheckVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.CheckEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})
}

func (impl *anonymousModelImpl) CheckRegisterEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.tokenManagerModel.CheckEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.SetupEvent,
	})
}

func (impl *anonymousModelImpl) SetAnonymousUserInfoAndMarkEventCompleted(ctx context.Context, bizID string, userID uint64, userName string) (status bizuserinters.Status) {
	if userID == 0 || userName == "" {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	status = impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.VerifyEvent,
	})

	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: impl.authenticatorIdentity,
		Event:         bizuserinters.SetupEvent,
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
