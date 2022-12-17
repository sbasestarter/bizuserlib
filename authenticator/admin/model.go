package admin

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	authenticator.Model

	SetAdminFlagCompleted(ctx context.Context, bizID string, userID uint64, adminFlag bool) (status bizuserinters.Status)
}
