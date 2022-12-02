package usermanager

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type APIModel interface {
	ListUsers(ctx context.Context) (users []*bizuserinters.UserInfo, status bizuserinters.Status)
}
