package authenticator

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
)

func NewDirectTokenManagerModel(tokenManager bizuserinters.TokenManager) authenticator.TokenManagerModel {
	if tokenManager == nil {
		return nil
	}

	return &directTokenManagerModelImpl{
		tokenManager: tokenManager,
	}
}

type directTokenManagerModelImpl struct {
	tokenManager bizuserinters.TokenManager
}

func (m *directTokenManagerModelImpl) GetCurrentEvents(ctx context.Context, bizID string) (es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return m.tokenManager.GetCurrentEvents(ctx, bizID)
}

func (m *directTokenManagerModelImpl) GetAllCompletedAuthenticatorEvents(ctx context.Context, bizID string) (es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return m.tokenManager.GetAllCompletedAuthenticatorEvents(ctx, bizID)
}

func (m *directTokenManagerModelImpl) MarkEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	return m.tokenManager.MarkAuthenticatorEventCompleted(ctx, bizID, e)
}

func (m *directTokenManagerModelImpl) CheckEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	return m.tokenManager.HasAuthenticatorEventCompleted(ctx, bizID, e)
}

func (m *directTokenManagerModelImpl) SetAuthenticatorData(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent, ds map[string]interface{}) (status bizuserinters.Status) {
	return m.tokenManager.SetAuthenticatorData(ctx, bizID, e, ds)
}

func (m *directTokenManagerModelImpl) SetCurrentUserInfo(ctx context.Context, bizID string, ui *bizuserinters.UserIdentity) (status bizuserinters.Status) {
	return m.tokenManager.SetCurrentUserInfo(ctx, bizID, ui)
}
func (m *directTokenManagerModelImpl) GetCurrentUserInfo(ctx context.Context, bizID string) (ui *bizuserinters.UserIdentity, status bizuserinters.Status) {
	return m.tokenManager.GetCurrentUserInfo(ctx, bizID)
}
