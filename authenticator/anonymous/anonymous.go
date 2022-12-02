package anonymous

import (
	"context"

	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Authenticator interface {
	bizuserinters.Authenticator

	SetUserName(ctx context.Context, bizID, userName string) bizuserinters.Status
}

func NewAuthenticator(model Model) Authenticator {
	if model == nil {
		return nil
	}

	return &authenticatorImpl{
		model: model,
	}
}

type authenticatorImpl struct {
	model Model
}

func (impl *authenticatorImpl) SetUserName(ctx context.Context, bizID, userName string) bizuserinters.Status {
	return impl.model.SetAnonymousUserInfoAndMarkEventCompleted(ctx, bizID, snowflake.ID(), userName)
}

func (impl *authenticatorImpl) VerifyCheck(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.model.CheckVerifyEventCompleted(ctx, bizID)
}

func (impl *authenticatorImpl) RegisterCheck(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.model.CheckRegisterEventCompleted(ctx, bizID)
}
