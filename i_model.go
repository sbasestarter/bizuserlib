package bizuserlib

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	AddUser(ctx context.Context, authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{},
		userIdentity *bizuserinters.UserIdentity) (userInfo *bizuserinters.UserInfoInner, status bizuserinters.Status)
	GetUserFromLogin(ctx context.Context, authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{},
		userIdentity *bizuserinters.UserIdentity) (userInfo *bizuserinters.UserInfoInner, status bizuserinters.Status)
	Update(ctx context.Context, userID uint64, authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{},
		userIdentity *bizuserinters.UserIdentity) (status bizuserinters.Status)
	Delete(ctx context.Context, authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{},
		userIdentity *bizuserinters.UserIdentity) (status bizuserinters.Status)
}
