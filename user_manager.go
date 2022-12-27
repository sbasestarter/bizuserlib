package bizuserlib

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/usermanager"
	"github.com/sgostarter/i/l"
)

const (
	workDataCaredAuthenticatorsKey = "caredAuthenticators"
)

func NewUserManager(tokenManager bizuserinters.TokenManager, userTokenManager bizuserinters.UserTokenManager,
	registerPolicy, loginPolicy, changePolicy, deletePolicy Policy, model Model, apiModel usermanager.APIModel,
	logger l.Wrapper) bizuserinters.UserManager {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if tokenManager == nil {
		logger.Error("no token manager")

		return nil
	}

	if userTokenManager == nil {
		logger.Error("no user token manager")

		return nil
	}

	if registerPolicy == nil {
		logger.Error("no register policy")

		return nil
	}

	if loginPolicy == nil {
		logger.Error("no login policy")

		return nil
	}

	if changePolicy == nil {
		logger.Error("no change policy")

		return nil
	}

	if deletePolicy == nil {
		logger.Error("no delete policy")

		return nil
	}

	if model == nil {
		logger.Error("no model")

		return nil
	}

	if apiModel == nil {
		logger.Error("no api model")

		return nil
	}

	return &userManagerImpl{
		logger:           logger.WithFields(l.StringField(l.ClsKey, "userManagerImpl")),
		tokenManager:     tokenManager,
		userTokenManager: userTokenManager,
		registerPolicy:   registerPolicy,
		loginPolicy:      loginPolicy,
		changePolicy:     changePolicy,
		deletePolicy:     deletePolicy,
		model:            model,
		apiModel:         apiModel,
	}
}

type userManagerImpl struct {
	logger           l.Wrapper
	tokenManager     bizuserinters.TokenManager
	userTokenManager bizuserinters.UserTokenManager
	registerPolicy   Policy
	loginPolicy      Policy
	changePolicy     Policy
	deletePolicy     Policy
	model            Model
	apiModel         usermanager.APIModel
}

func (impl *userManagerImpl) RegisterBegin(ctx context.Context) (bizID string, neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return impl.xBegin(ctx, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.SetupEvent,
	}, nil)
}

func (impl *userManagerImpl) RegisterCheck(ctx context.Context, bizID string) (neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.SetupEvent,
	}, false)
}

func (impl *userManagerImpl) RegisterEnd(ctx context.Context, bizID string) (userID uint64, token string, status bizuserinters.Status) {
	defer impl.tokenManager.DeleteToken(bizID)

	_, status = impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.SetupEvent,
	}, false)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	ds, status := impl.tokenManager.GetAllAuthenticatorDatas(ctx, bizID, bizuserinters.SetupEvent)
	userIdentity, _ := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)

	userInfo, status := impl.model.AddUser(ctx, ds, userIdentity)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	userID = userInfo.ID

	token, status = impl.userTokenManager.GenToken(ctx, &bizuserinters.UserTokenInfo{
		ID:       userInfo.ID,
		UserName: userInfo.UserName,
		Age:      time.Hour * 24 * 7,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return
}

func (impl *userManagerImpl) LoginBegin(ctx context.Context) (bizID string, neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return impl.xBegin(ctx, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.VerifyEvent,
	}, nil)
}

func (impl *userManagerImpl) LoginCheck(ctx context.Context, bizID string) (neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.VerifyEvent,
	}, false)
}

func (impl *userManagerImpl) LoginEnd(ctx context.Context, bizID string) (userID uint64, token string, status bizuserinters.Status) {
	defer impl.tokenManager.DeleteToken(bizID)

	_, status = impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.VerifyEvent,
	}, false)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	ds, _ := impl.tokenManager.GetAllAuthenticatorDatas(ctx, bizID, bizuserinters.VerifyEvent)

	userIdentity, _ := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)

	userInfo, status := impl.model.GetUserFromLogin(ctx, ds, userIdentity)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	userID = userInfo.ID

	token, status = impl.userTokenManager.GenToken(ctx, &bizuserinters.UserTokenInfo{
		ID:       userID,
		UserName: userInfo.UserName,
		Age:      time.Hour * 24 * 7,
	})

	return
}

func (impl *userManagerImpl) ChangeBegin(ctx context.Context, token string, authenticators []bizuserinters.AuthenticatorIdentity) (
	bizID string, neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	userTokenInfo, status := impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return impl.xBeginEx(ctx, bizuserinters.AuthenticatorEvent{
		Event: bizuserinters.ChangeEvent,
	}, authenticators, func(bizID string) bizuserinters.Status {
		return impl.tokenManager.SetCurrentUserInfo(ctx, bizID, &bizuserinters.UserIdentity{
			ID:       userTokenInfo.ID,
			UserName: userTokenInfo.UserName,
		})
	})
}

func (impl *userManagerImpl) ChangeCheck(ctx context.Context, bizID string) (neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Event: bizuserinters.ChangeEvent,
	}, true)
}

func (impl *userManagerImpl) ChangeEnd(ctx context.Context, bizID string) (status bizuserinters.Status) {
	defer impl.tokenManager.DeleteToken(bizID)

	_, status = impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Event: bizuserinters.ChangeEvent,
	}, true)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	ds, status := impl.tokenManager.GetAllAuthenticatorDatas(ctx, bizID, bizuserinters.SetupEvent)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	userIdentity, _ := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)

	status = impl.model.Update(ctx, userIdentity.ID, ds, userIdentity)

	return
}

func (impl *userManagerImpl) DeleteBegin(ctx context.Context, token string, authenticators []bizuserinters.AuthenticatorIdentity) (bizID string, neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	userTokenInfo, status := impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return impl.xBeginEx(ctx, bizuserinters.AuthenticatorEvent{
		Event: bizuserinters.DeleteEvent,
	}, authenticators, func(bizID string) bizuserinters.Status {
		return impl.tokenManager.SetCurrentUserInfo(ctx, bizID, &bizuserinters.UserIdentity{
			ID:       userTokenInfo.ID,
			UserName: userTokenInfo.UserName,
		})
	})
}

func (impl *userManagerImpl) DeleteCheck(ctx context.Context, bizID string) (neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	return impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Event: bizuserinters.DeleteEvent,
	}, true)
}

func (impl *userManagerImpl) DeleteEnd(ctx context.Context, bizID string) (status bizuserinters.Status) {
	defer impl.tokenManager.DeleteToken(bizID)

	_, status = impl.xCheck(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Event: bizuserinters.DeleteEvent,
	}, true)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	caredAuthenticators, status := impl.getWorkData4CaredAuthenticators(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	userIdentity, _ := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)

	var fields uint64

	for _, authenticator := range caredAuthenticators {
		if authenticator == bizuserinters.AuthenticatorGoogle2FA {
			fields |= bizuserinters.DeleteFieldGoogle2FA
		}
	}

	status = impl.model.Delete(ctx, userIdentity.ID, fields, userIdentity)

	return
}

func (impl *userManagerImpl) ListUsers(ctx context.Context, token string) (users []*bizuserinters.UserInfo, status bizuserinters.Status) {
	_, status = impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return impl.apiModel.ListUsers(ctx)
}

func (impl *userManagerImpl) CheckToken(ctx context.Context, token string) (info *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	return impl.userTokenManager.ExplainToken(ctx, token)
}

func (impl *userManagerImpl) RenewToken(ctx context.Context, token string) (newToken string, info *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	return impl.userTokenManager.RenewToken(ctx, token)
}

func (impl *userManagerImpl) Logout(ctx context.Context, token string) bizuserinters.Status {
	return impl.userTokenManager.DeleteToken(ctx, token)
}

//
//
//

func (impl *userManagerImpl) getPolicyByPurpose(purpose bizuserinters.Event) Policy {
	var policy Policy

	switch purpose {
	case bizuserinters.SetupEvent:
		policy = impl.registerPolicy
	case bizuserinters.VerifyEvent:
		policy = impl.loginPolicy
	case bizuserinters.ChangeEvent:
		policy = impl.changePolicy
	case bizuserinters.DeleteEvent:
		policy = impl.deletePolicy
	}

	return policy
}

func (impl *userManagerImpl) xBegin(ctx context.Context, purpose bizuserinters.AuthenticatorEvent,
	authenticators []bizuserinters.AuthenticatorIdentity) (bizID string, neededOrEvent []bizuserinters.AuthenticatorEvent,
	status bizuserinters.Status) {
	return impl.xBeginEx(ctx, purpose, authenticators, nil)
}

func (impl *userManagerImpl) xBeginEx(ctx context.Context, purpose bizuserinters.AuthenticatorEvent,
	authenticators []bizuserinters.AuthenticatorIdentity, newTokenCreatedCB func(bizID string) bizuserinters.Status) (bizID string, neededOrEvent []bizuserinters.AuthenticatorEvent,
	status bizuserinters.Status) {
	defer func() {
		if status.Code != bizuserinters.StatusCodeOk && status.Code != bizuserinters.StatusCodeNeedAuthenticator {
			impl.tokenManager.DeleteToken(bizID)
		}
	}()

	bizID, status = impl.tokenManager.CreateToken(ctx)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	policy := impl.getPolicyByPurpose(purpose.Event)
	if policy == nil {
		status.Code = bizuserinters.StatusCodeNotImplementError

		return
	}

	if len(authenticators) > 0 {
		d, _ := json.Marshal(authenticators)

		status = impl.tokenManager.SetWorkData(ctx, bizID, workDataCaredAuthenticatorsKey, d)
		if status.Code != bizuserinters.StatusCodeOk {
			return
		}

		purpose.Authenticator = authenticators[0]
	}

	if newTokenCreatedCB != nil {
		status = newTokenCreatedCB(bizID)
		if status.Code != bizuserinters.StatusCodeOk {
			return
		}
	}

	neededOrEvent, status = policy.Check(ctx, CheckPolicyData{
		BizID:   bizID,
		Purpose: purpose,
	})

	return
}

func (impl *userManagerImpl) xCheck(ctx context.Context, bizID string, purpose bizuserinters.AuthenticatorEvent, useCaredAuthenticators bool) (neededOrEvent []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	completedEvents, status := impl.tokenManager.GetAllCompletedAuthenticatorEvents(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	policy := impl.getPolicyByPurpose(purpose.Event)
	if policy == nil {
		status.Code = bizuserinters.StatusCodeNotImplementError

		return
	}

	if useCaredAuthenticators {
		var caredAuthenticators []bizuserinters.AuthenticatorIdentity
		caredAuthenticators, status = impl.getWorkData4CaredAuthenticators(ctx, bizID)

		if status.Code != bizuserinters.StatusCodeOk {
			return
		}

		if len(caredAuthenticators) == 0 {
			status.Code = bizuserinters.StatusCodeNoDataError

			return
		}

		purpose.Authenticator = caredAuthenticators[0]
	}

	neededOrEvent, status = policy.Check(ctx, CheckPolicyData{
		BizID:      bizID,
		Purpose:    purpose,
		DoneEvents: completedEvents,
	})

	return
}

func (impl *userManagerImpl) getWorkData4CaredAuthenticators(ctx context.Context, bizID string) (
	caredAuthenticators []bizuserinters.AuthenticatorIdentity, status bizuserinters.Status) {
	val, status := impl.tokenManager.GetWorkData(ctx, bizID, workDataCaredAuthenticatorsKey)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	err := json.Unmarshal(val, &caredAuthenticators)
	if err != nil {
		status.Code = bizuserinters.StatusCodeInternalError

		return
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}
