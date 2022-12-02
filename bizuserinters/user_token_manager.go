package bizuserinters

import (
	"context"
	"time"
)

type UserTokenInfo struct {
	ID       uint64
	UserName string
	Age      time.Duration
}

type UserTokenManager interface {
	GenToken(ctx context.Context, userInfo *UserTokenInfo) (string, Status)
	DeleteToken(ctx context.Context, token string) Status
	ExplainToken(ctx context.Context, token string) (*UserTokenInfo, Status)
	RenewToken(ctx context.Context, token string) (string, *UserTokenInfo, Status)
}
