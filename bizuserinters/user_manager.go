package bizuserinters

import (
	"context"
)

type UserInfo struct {
	ID           uint64
	UserName     string
	HasGoogle2FA bool
	Admin        bool
}

type UserManager interface {
	RegisterBegin(ctx context.Context, ssoJumpURL string) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	RegisterCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	RegisterEnd(ctx context.Context, bizID string) (userID uint64, token, ssoToken string, status Status)

	LoginBegin(ctx context.Context, ssoJumpURL string) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	LoginCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	LoginEnd(ctx context.Context, bizID string) (userID uint64, token, ssoToken string, status Status)

	ChangeBegin(ctx context.Context, token string, authenticators []AuthenticatorIdentity) (
		bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	ChangeCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	ChangeEnd(ctx context.Context, bizID string) (status Status)

	DeleteBegin(ctx context.Context, token string, authenticators []AuthenticatorIdentity) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	DeleteCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	DeleteEnd(ctx context.Context, bizID string) (status Status)

	ListUsers(ctx context.Context, token string) (users []*UserInfo, status Status)
	CheckToken(ctx context.Context, token string, ssoJumpURL string) (ssoToken string, info *UserTokenInfo, status Status)
	RenewToken(ctx context.Context, token string) (newToken string, info *UserTokenInfo, status Status)
	Logout(ctx context.Context, token string) Status
}
