package model

import (
	"context"

	adminmodel "github.com/sbasestarter/bizuserlib/authenticator/admin"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/admin"
)

const (
	adminSetFlagUserID = "admin:user_id"
	adminSetFlagFlag   = "admin:flag"
)

func NewAdminModel(dbModel admin.DBModel, tokenManagerModel authenticator.TokenManagerModel) adminmodel.Model {
	if dbModel == nil || tokenManagerModel == nil {
		return nil
	}

	return &adminModelImpl{
		Base: Base{
			TokenManager: tokenManagerModel,
		},
		dbModel:           dbModel,
		tokenManagerModel: tokenManagerModel,
	}
}

type adminModelImpl struct {
	Base
	dbModel           admin.DBModel
	tokenManagerModel authenticator.TokenManagerModel
}

func (impl *adminModelImpl) SetAdminFlagCompleted(ctx context.Context, bizID string, userID uint64, adminFlag bool) (status bizuserinters.Status) {
	isAdmin, status := impl.dbModel.IsAdmin(ctx, bizID)
	if status.Code == bizuserinters.StatusCodeOk {
		return
	}

	if isAdmin {
		status.Code = bizuserinters.StatusCodePermissionError

		return
	}

	status = impl.tokenManagerModel.SetAuthenticatorData(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorAdminFlag,
		Event:         bizuserinters.SetupEvent,
	}, map[string]interface{}{
		adminSetFlagFlag:   adminFlag,
		adminSetFlagUserID: userID,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status = impl.tokenManagerModel.MarkEventCompleted(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorAdminFlag,
		Event:         bizuserinters.SetupEvent,
	})

	return
}
