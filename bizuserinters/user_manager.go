package bizuserinters

import (
	"context"
)

type UserInfo struct {
	ID           uint64
	UserName     string
	HasGoogle2FA bool
}

type UserManager interface {
	RegisterBegin(ctx context.Context) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	RegisterCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	RegisterEnd(ctx context.Context, bizID string) (userID uint64, token string, status Status)

	LoginBegin(ctx context.Context) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	LoginCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	LoginEnd(ctx context.Context, bizID string) (userID uint64, token string, status Status)

	ChangeBegin(ctx context.Context, token string, authenticators []AuthenticatorIdentity) (
		bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	ChangeCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	ChangeEnd(ctx context.Context, bizID string) (status Status)

	DeleteBegin(ctx context.Context, authenticators []AuthenticatorIdentity) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	DeleteCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	DeleteEnd(ctx context.Context, bizID string) (status Status)

	ListUsers(ctx context.Context) (users []*UserInfo, status Status)
	CheckToken(ctx context.Context, token string) (info *UserTokenInfo, status Status)
	RenewToken(ctx context.Context, token string) (newToken string, info *UserTokenInfo, status Status)
}
