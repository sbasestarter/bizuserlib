package userpass

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	authenticator.Model

	GetUserPassInfoByUserName(ctx context.Context, bizID string, userName string) (userID uint64, password string, status bizuserinters.Status)
	GetUserPassInfo(ctx context.Context, bizID string) (userID uint64, userName, password string, status bizuserinters.Status)

	SetSetupCompleted(ctx context.Context, bizID string, userName string, password string) (status bizuserinters.Status)
	SetLoginCompleted(ctx context.Context, bizID string, userID uint64, userName string) (status bizuserinters.Status)
	SetVerifyPasswordCompleted(ctx context.Context, bizID string) (status bizuserinters.Status)
	SetChangePasswordCompleted(ctx context.Context, bizID string, password string) (status bizuserinters.Status)
}
