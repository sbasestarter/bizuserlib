package google2fa

import (
	"context"

	"github.com/sbasestarter/bizuserlib/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	authenticatorlib "github.com/sgostarter/libeasygo/authenticator"
)

type Authenticator interface {
	bizuserinters.Authenticator

	GetSetupInfo(ctx context.Context, bizID string) (secretKey, qrCode string, status bizuserinters.Status)
	DoSetup(ctx context.Context, bizID, code string) (status bizuserinters.Status)

	Verify(ctx context.Context, bizID, code string) (status bizuserinters.Status)
}

func NewAuthenticator(model Model, issuer string) Authenticator {
	if model == nil {
		return nil
	}

	return &authenticatorImpl{
		Authenticator: authenticator.Authenticator{
			Model:         model,
			Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		},
		model:  model,
		issuer: issuer,
	}
}

type authenticatorImpl struct {
	authenticator.Authenticator

	model  Model
	issuer string
}

//
//
//

func (impl *authenticatorImpl) GetSetupInfo(ctx context.Context, bizID string) (secretKey, qrCode string, status bizuserinters.Status) {
	secretKey, status = impl.model.GetGoogle2FASecretKey(ctx, bizID)
	id, status := impl.model.GetGoogle2FASetupUserInfo(ctx, bizID)

	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	secretKey = authenticatorlib.GetSecret()
	qrCode = authenticatorlib.CreateGoogleAuthQRCodeData(secretKey, id, impl.issuer)

	status = impl.model.CacheGoogle2FASecretKey(ctx, bizID, secretKey)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	return
}

func (impl *authenticatorImpl) DoSetup(ctx context.Context, bizID, code string) (status bizuserinters.Status) {
	secretKey, status := impl.model.GetCachedGoogle2FASecretKey(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	calcCode, err := authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	if err != nil {
		status.Code = bizuserinters.StatusCodeInternalError

		return
	}

	if calcCode != code {
		status.Code = bizuserinters.StatusCodeVerifyError

		return
	}

	status = impl.model.SetGoogle2FASecretKeyAndMarkRegisterEventCompleted(ctx, bizID, secretKey)

	return status
}

func (impl *authenticatorImpl) Verify(ctx context.Context, bizID, code string) (status bizuserinters.Status) {
	secretKey, status := impl.model.GetGoogle2FASecretKey(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	calcCode, err := authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	if err != nil {
		status.Code = bizuserinters.StatusCodeInternalError

		return
	}

	if calcCode != code {
		status.Code = bizuserinters.StatusCodeVerifyError

		return
	}

	status = impl.model.MarkVerifyEventCompleted(ctx, bizID)

	return
}
