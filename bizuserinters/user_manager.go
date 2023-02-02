package bizuserinters

import (
	"context"
	"time"
)

type UserInfo struct {
	ID           uint64
	UserName     string
	HasGoogle2FA bool
	Admin        bool
}

type TokenInfo struct {
	Token      string
	Expiration time.Duration
}

type UserManager interface {
	RegisterBegin(ctx context.Context) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	RegisterCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	RegisterEnd(ctx context.Context, bizID string) (userInfo *UserInfo, status Status)

	LoginBegin(ctx context.Context) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	LoginCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	LoginEnd(ctx context.Context, bizID string) (userInfo *UserInfo, status Status)

	ChangeBegin(ctx context.Context, userID uint64, userName string, authenticators []AuthenticatorIdentity) (
		bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	ChangeCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	ChangeEnd(ctx context.Context, bizID string) (status Status)

	DeleteBegin(ctx context.Context, userID uint64, userName string, authenticators []AuthenticatorIdentity) (bizID string, neededOrEvent []AuthenticatorEvent, status Status)
	DeleteCheck(ctx context.Context, bizID string) (neededOrEvent []AuthenticatorEvent, status Status)
	DeleteEnd(ctx context.Context, bizID string) (status Status)

	ListUsers(ctx context.Context) (users []*UserInfo, status Status)
}
