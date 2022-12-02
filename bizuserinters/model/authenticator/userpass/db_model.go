package userpass

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type DBModel interface {
	GetUserPassInfoByUserName(ctx context.Context, bizID string, userName string) (userID uint64, password string, status bizuserinters.Status)
	GetUserPassInfo(ctx context.Context, bizID string) (userID uint64, userName, password string, status bizuserinters.Status)
}
