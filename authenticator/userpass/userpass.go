package userpass

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/libeasygo/crypt"
)

type Authenticator interface {
	Register(ctx context.Context, bizID string, userName, password string) bizuserinters.Status
	Login(ctx context.Context, bizID string, userName, password string) bizuserinters.Status
	VerifyPassword(ctx context.Context, bizID string, password string) bizuserinters.Status
	ChangePassword(ctx context.Context, bizID string, password string) bizuserinters.Status
}

func NewAuthenticator(model Model, passwordSecret string) Authenticator {
	if model == nil {
		return nil
	}

	return &authenticatorImpl{
		model:          model,
		passwordSecret: passwordSecret,
	}
}

type authenticatorImpl struct {
	model          Model
	passwordSecret string
}

func (impl *authenticatorImpl) Register(ctx context.Context, bizID string, userName, password string) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.SetupEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if userName == "" || password == "" {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	_, _, status = impl.model.GetUserPassInfoByUserName(ctx, bizID, userName)
	if status.Code == bizuserinters.StatusCodeOk {
		status.Code = bizuserinters.StatusCodeDupError

		return
	}

	status = impl.model.SetSetupCompleted(ctx, bizID, userName, impl.passEncrypt(password))

	return
}

func (impl *authenticatorImpl) Login(ctx context.Context, bizID string, userName, password string) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.VerifyEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if userName == "" || password == "" {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	userID, dbPassword, status := impl.model.GetUserPassInfoByUserName(ctx, bizID, userName)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if dbPassword != impl.passEncrypt(password) {
		status.Code = bizuserinters.StatusCodeVerifyError

		return
	}

	status = impl.model.SetLoginCompleted(ctx, bizID, userID, userName)

	return
}

func (impl *authenticatorImpl) VerifyPassword(ctx context.Context, bizID string, password string) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.VerifyEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	_, _, dbPassword, status := impl.model.GetUserPassInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if dbPassword != impl.passEncrypt(password) {
		status.Code = bizuserinters.StatusCodeVerifyError

		return
	}

	status = impl.model.SetVerifyPasswordCompleted(ctx, bizID)

	return
}

func (impl *authenticatorImpl) ChangePassword(ctx context.Context, bizID string, newPassword string) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.SetupEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if newPassword == "" {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	_, _, dbPassword, status := impl.model.GetUserPassInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if dbPassword == impl.passEncrypt(newPassword) {
		status.Code = bizuserinters.StatusCodeDupError

		return
	}

	status = impl.model.SetChangePasswordCompleted(ctx, bizID, impl.passEncrypt(newPassword))

	return
}

func (impl *authenticatorImpl) passEncrypt(content string) string {
	encryptD, _ := crypt.HMacSHa256(impl.passwordSecret, content)

	return encryptD
}
