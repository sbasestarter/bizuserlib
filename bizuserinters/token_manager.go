package bizuserinters

import (
	"context"
)

type AdminFlag struct {
	UserID uint64
	Flag   bool
}

type UserInfoInner struct {
	UserIdentity
	Password           string
	Google2FASecretKey string
	AdminFlags         []AdminFlag
}

type UserIdentity struct {
	ID       uint64
	UserName string
}

type TokenManager interface {
	CreateToken(ctx context.Context) (bizID string, status Status)
	DeleteToken(bizID string)

	MarkAuthenticatorEventCompleted(ctx context.Context, bizID string, e AuthenticatorEvent) Status
	HasAuthenticatorEventCompleted(ctx context.Context, bizID string, e AuthenticatorEvent) (status Status)
	GetAllCompletedAuthenticatorEvents(ctx context.Context, bizID string) (es []AuthenticatorEvent, status Status)

	SetAuthenticatorData(ctx context.Context, bizID string, e AuthenticatorEvent, ds map[string]interface{}) (status Status)
	GetAllAuthenticatorDatas(ctx context.Context, bizID string, e Event) (ds map[AuthenticatorIdentity]map[string]interface{}, status Status)

	SetWorkData(ctx context.Context, bizID string, key string, d []byte) (status Status)
	GetWorkData(ctx context.Context, bizID string, key string) (d []byte, status Status)

	//
	//
	//

	SetCurrentUserInfo(ctx context.Context, bizID string, ui *UserIdentity) (status Status)
	GetCurrentUserInfo(ctx context.Context, bizID string) (ui *UserIdentity, status Status)

	//
	//
	//

	GetCurrentEvents(ctx context.Context, bizID string) (es []AuthenticatorEvent, status Status)
}

type TokenManager4Policy interface {
	TokenManager

	SetCurrentEvents(ctx context.Context, bizID string, es []AuthenticatorEvent) Status
	ClearCurrentEvents(ctx context.Context, bizID string) Status
}

type TokenManagerAll interface {
	TokenManager4Policy
}
