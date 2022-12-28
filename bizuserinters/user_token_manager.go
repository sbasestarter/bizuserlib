package bizuserinters

import (
	"context"
	"time"
)

type UserTokenInfo struct {
	ID       uint64
	UserName string
	StartAt  time.Time
	Age      time.Duration
}

type UserTokenManager interface {
	GenToken(ctx context.Context, userInfo *UserTokenInfo) (string, Status)
	ExplainToken(ctx context.Context, token string) (*UserTokenInfo, Status)
	RenewToken(ctx context.Context, token string) (string, *UserTokenInfo, Status)

	GenSSOToken(ctx context.Context, parentToken string, expiration time.Duration) (string, Status)
	ExplainSSOToken(ctx context.Context, token string) (*UserTokenInfo, Status)

	DeleteToken(ctx context.Context, token string) Status
}
