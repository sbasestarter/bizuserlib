package authenticator

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	CheckEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status)
	MustCurrentEvent(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status)
}
