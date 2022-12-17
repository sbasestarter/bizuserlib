package google2fa

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	authenticator.Model

	GetGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status)
	GetGoogle2FASetupUserInfo(ctx context.Context, bizID string) (name string, status bizuserinters.Status)

	CacheGoogle2FASecretKey(ctx context.Context, bizID, secretKey string) (status bizuserinters.Status)
	GetCachedGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status)

	SetSetupGoogle2FACompleted(ctx context.Context, bizID string, secretKey string) (status bizuserinters.Status)
	SetVerifyGoogle2FACompleted(ctx context.Context, bizID string) (status bizuserinters.Status)
}
