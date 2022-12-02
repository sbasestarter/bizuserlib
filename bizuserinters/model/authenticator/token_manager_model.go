package authenticator

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type TokenManagerModel interface {
	MarkEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status)
	CheckEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status)
	SetAuthenticatorData(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent, ds map[string]interface{}) (status bizuserinters.Status)

	SetCurrentUserInfo(ctx context.Context, bizID string, ui *bizuserinters.UserIdentity) (status bizuserinters.Status)
	GetCurrentUserInfo(ctx context.Context, bizID string) (ui *bizuserinters.UserIdentity, status bizuserinters.Status)
}
