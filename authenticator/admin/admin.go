package admin

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Authenticator interface {
	SetAdmin(ctx context.Context, bizID string, userID uint64, adminFlag bool) bizuserinters.Status
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

func (impl *authenticatorImpl) SetAdmin(ctx context.Context, bizID string, userID uint64, adminFlag bool) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorAdminFlag,
		Event:         bizuserinters.SetupEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.model.SetAdminFlagCompleted(ctx, bizID, userID, adminFlag)

	return
}
