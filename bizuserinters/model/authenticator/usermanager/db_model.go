package usermanager

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type DBModel interface {
	AddUser(ctx context.Context, userInfo *bizuserinters.UserInfoInner) (status bizuserinters.Status)
	UpdateUser(ctx context.Context, userInfo *bizuserinters.UserInfoInner) (status bizuserinters.Status)
	Delete(ctx context.Context, userID uint64, fields uint64) (status bizuserinters.Status)
}
