package admin

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type DBModel interface {
	IsAdmin(ctx context.Context, bizID string) (adminFlag bool, status bizuserinters.Status)
}
