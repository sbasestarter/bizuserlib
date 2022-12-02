package userpass

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/libeasygo/crypt"
)

type Authenticator interface {
	bizuserinters.Authenticator
	VerifyUserPass(ctx context.Context, bizID string, userName, password string) bizuserinters.Status
	RegisterUserPass(ctx context.Context, bizID string, userName, password string) bizuserinters.Status
	VerifyPassword(ctx context.Context, bizID string, password string) bizuserinters.Status
	ChangePassword(ctx context.Context, bizID string, password string) bizuserinters.Status
}

func NewAuthenticator(model Model, passwordSecret string) Authenticator {
	if model == nil {
		return nil
	}

	return &authenticatorImpl{
		Authenticator: authenticator.Authenticator{
			Model:         model,
			Authenticator: bizuserinters.AuthenticatorUserPass,
		},
		model:          model,
		passwordSecret: passwordSecret,
	}
}

type authenticatorImpl struct {
	authenticator.Authenticator

	model          Model
	passwordSecret string
}

func (impl *authenticatorImpl) VerifyUserPass(ctx context.Context, bizID string, userName, password string) (status bizuserinters.Status) {
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

	status = impl.model.SetVerifiedUserInfoAndMarkVerifyEventCompleted(ctx, bizID, userID, userName)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return
}

func (impl *authenticatorImpl) VerifyCheck(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.model.CheckVerifyEventCompleted(ctx, bizID)
}

func (impl *authenticatorImpl) RegisterUserPass(ctx context.Context, bizID string, userName, password string) (status bizuserinters.Status) {
	if userName == "" || password == "" {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	status = impl.model.AddUserAndMarkRegisterEventCompleted(ctx, bizID, userName, impl.passEncrypt(password))
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return
}

func (impl *authenticatorImpl) VerifyPassword(ctx context.Context, bizID string, password string) (status bizuserinters.Status) {
	_, _, dbPassword, status := impl.model.GetUserPassInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if dbPassword != impl.passEncrypt(password) {
		status.Code = bizuserinters.StatusCodeVerifyError

		return
	}

	status = impl.model.MarkVerifyEventCompleted(ctx, bizID)

	return
}

func (impl *authenticatorImpl) ChangePassword(ctx context.Context, bizID string, newPassword string) (status bizuserinters.Status) {
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

	status = impl.model.SetNewPasswordAndMarkChangeEventCompleted(ctx, bizID, impl.passEncrypt(newPassword))

	return
}

func (impl *authenticatorImpl) RegisterCheck(ctx context.Context, bizID string) (status bizuserinters.Status) {
	return impl.model.CheckRegisterEventCompleted(ctx, bizID)
}

func (impl *authenticatorImpl) passEncrypt(content string) string {
	encryptD, _ := crypt.HMacSHa256(impl.passwordSecret, content)

	return encryptD
}
