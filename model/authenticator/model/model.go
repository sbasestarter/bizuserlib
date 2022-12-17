package model

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	authenticatorinters "github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
)

type Base struct {
	TokenManager authenticatorinters.TokenManagerModel
}

func (impl *Base) CheckEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	es, status := impl.TokenManager.GetAllCompletedAuthenticatorEvents(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	for _, event := range es {
		if e.Equal(event) {
			status.Code = bizuserinters.StatusCodeOk

			return
		}
	}

	status.Code = bizuserinters.StatusCodeNoDataError

	return
}

func (impl *Base) MustCurrentEvent(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	es, status := impl.TokenManager.GetCurrentEvents(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	for _, event := range es {
		if e.Equal(event) {
			status.Code = bizuserinters.StatusCodeOk

			return
		}
	}

	status.Code = bizuserinters.StatusCodeNoDataError

	return
}
