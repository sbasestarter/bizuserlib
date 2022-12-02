package authenticator

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Authenticator struct {
	Model         Model
	Authenticator bizuserinters.AuthenticatorIdentity
}

func (authenticator *Authenticator) VerifyCheck(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return authenticator.Model.CheckVerifyEventCompleted(ctx, bizID)
}

func (authenticator *Authenticator) RegisterCheck(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return authenticator.Model.CheckRegisterEventCompleted(ctx, bizID)
}
