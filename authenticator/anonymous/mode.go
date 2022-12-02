package anonymous

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	authenticator.Model

	SetAnonymousUserInfoAndMarkEventCompleted(ctx context.Context, bizID string, userID uint64, userName string) (status bizuserinters.Status)
}
