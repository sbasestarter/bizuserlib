package model

import (
	"context"

	"github.com/sbasestarter/bizuserlib"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/usermanager"
	"github.com/spf13/cast"
)

func NewUserManagerModel(m usermanager.DBModel) bizuserlib.Model {
	if m == nil {
		return nil
	}

	return &userManagerModel{
		m: m,
	}
}

type userManagerModel struct {
	m usermanager.DBModel
}

func (impl *userManagerModel) AddUser(ctx context.Context,
	authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{}, _ *bizuserinters.UserIdentity) (
	userInfo *bizuserinters.UserInfoInner, status bizuserinters.Status) {
	userInfo = impl.buildUserInfoFromAuthenticatorData(authenticatorData)

	if userInfo.UserName == "" || userInfo.Password == "" {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	status = impl.m.AddUser(ctx, userInfo)

	return
}

func (impl *userManagerModel) Update(ctx context.Context, userID uint64, authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{}, userIdentity *bizuserinters.UserIdentity) (status bizuserinters.Status) {
	userInfo := impl.buildUserInfoFromAuthenticatorData(authenticatorData)
	if userInfo.ID == 0 {
		userInfo.ID = userID
	}

	if userInfo.ID != userID {
		status.Code = bizuserinters.StatusCodeDupError

		return
	}

	status = impl.m.UpdateUser(ctx, userInfo)

	return
}

func (impl *userManagerModel) Delete(ctx context.Context, authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{}, userIdentity *bizuserinters.UserIdentity) (status bizuserinters.Status) {
	userInfo := impl.buildUserInfoFromAuthenticatorData(authenticatorData)

	status = impl.m.UpdateUser(ctx, userInfo)

	return
}

func (impl *userManagerModel) GetUserFromLogin(_ context.Context,
	authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{}, identity *bizuserinters.UserIdentity) (
	userInfo *bizuserinters.UserInfoInner, status bizuserinters.Status) {
	userInfo = impl.buildUserInfoFromAuthenticatorData(authenticatorData)

	if userInfo.ID == 0 || userInfo.UserName == "" {
		if identity != nil {
			userInfo = &bizuserinters.UserInfoInner{
				UserIdentity: *identity,
			}

			status.Code = bizuserinters.StatusCodeOk
		} else {
			status.Code = bizuserinters.StatusCodeNoDataError
		}

		return
	}

	if identity != nil {
		if identity.ID != userInfo.ID || identity.UserName != userInfo.UserName {
			status.Code = bizuserinters.StatusCodeConflictError

			return
		}
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

//
//
//

func (impl *userManagerModel) buildUserInfoFromAuthenticatorData(authenticatorData map[bizuserinters.AuthenticatorIdentity]map[string]interface{}) (userInfo *bizuserinters.UserInfoInner) {
	userInfo = &bizuserinters.UserInfoInner{}

	for identity, m := range authenticatorData {
		switch identity {
		case bizuserinters.AuthenticatorUserPass:
			userInfo.ID = cast.ToUint64(m[userPassUserID])
			userInfo.UserName = cast.ToString(m[userPassUsername])
			userInfo.Password = cast.ToString(m[userPassPassword])
		case bizuserinters.AuthenticatorPhone:
		case bizuserinters.AuthenticatorEmail:
		case bizuserinters.AuthenticatorGoogle2FA:
			userInfo.Google2FASecretKey = cast.ToString(m[google2FASecretKey])
		}
	}

	return
}
