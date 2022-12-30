package google2fa

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	authenticatorlib "github.com/sgostarter/libeasygo/authenticator"
)

type Authenticator interface {
	GetSetupInfo(ctx context.Context, bizID string) (secretKey, qrCode string, status bizuserinters.Status)
	DoSetup(ctx context.Context, bizID, code string) (status bizuserinters.Status)

	Verify(ctx context.Context, bizID, code string) (status bizuserinters.Status)
}

func NewAuthenticator(model Model, issuer string) Authenticator {
	return NewAuthenticatorEx(model, issuer, nil)
}

type DebugConfig struct {
	FakeQrURL     string
	FakeSecretKey string
}

func NewAuthenticatorEx(model Model, issuer string, dc *DebugConfig) Authenticator {
	if model == nil {
		return nil
	}

	return &authenticatorImpl{
		model:  model,
		issuer: issuer,
		dc:     dc,
	}
}

type authenticatorImpl struct {
	model  Model
	issuer string
	dc     *DebugConfig
}

//
//
//

func (impl *authenticatorImpl) GetSetupInfo(ctx context.Context, bizID string) (secretKey, qrCode string, status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	id, status := impl.model.GetGoogle2FASetupUserInfo(ctx, bizID)

	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if impl.dc != nil && impl.dc.FakeQrURL != "" {
		secretKey = impl.dc.FakeSecretKey
		qrCode = impl.dc.FakeQrURL
	} else {
		secretKey = authenticatorlib.GetSecret()
		qrCode = authenticatorlib.CreateGoogleAuthQRCodeData(secretKey, id, impl.issuer)
	}

	status = impl.model.CacheGoogle2FASecretKey(ctx, bizID, secretKey)

	return
}

func (impl *authenticatorImpl) DoSetup(ctx context.Context, bizID, code string) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

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

	status = impl.model.SetSetupGoogle2FACompleted(ctx, bizID, secretKey)

	return status
}

func (impl *authenticatorImpl) Verify(ctx context.Context, bizID, code string) (status bizuserinters.Status) {
	status = impl.model.MustCurrentEvent(ctx, bizID, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

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

	status = impl.model.SetVerifyGoogle2FACompleted(ctx, bizID)

	return
}
