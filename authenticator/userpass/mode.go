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

	MarkVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status)
	SetVerifiedUserInfoAndMarkVerifyEventCompleted(ctx context.Context, bizID string, userID uint64, userName string) (status bizuserinters.Status)
	AddUserAndMarkRegisterEventCompleted(ctx context.Context, bizID string, userName string, password string) (status bizuserinters.Status)
	SetNewPasswordAndMarkChangeEventCompleted(ctx context.Context, bizID string, password string) (status bizuserinters.Status)
}
