package policy

import (
	"context"

	"github.com/sbasestarter/bizuserlib"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func NewSerialAuthenticatorPolicy(tokenManager bizuserinters.TokenManager4Policy, authenticatorEvents ...bizuserinters.AuthenticatorEvent) bizuserlib.Policy {
	if tokenManager == nil || len(authenticatorEvents) == 0 {
		return nil
	}

	return &serial2AuthenticatorPolicyImpl{
		tokenManager:        tokenManager,
		authenticatorEvents: authenticatorEvents,
	}
}

type serial2AuthenticatorPolicyImpl struct {
	tokenManager        bizuserinters.TokenManager4Policy
	authenticatorEvents []bizuserinters.AuthenticatorEvent
}

func (impl *serial2AuthenticatorPolicyImpl) Check(ctx context.Context, d bizuserlib.CheckPolicyData) (neededOrEvents []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	for _, event := range impl.authenticatorEvents {
		var done bool

		for _, doneEvent := range d.DoneEvents {
			if event.Equal(doneEvent) {
				done = true

				break
			}
		}

		if !done {
			neededOrEvents = append(neededOrEvents, event)

			status = impl.tokenManager.SetCurrentEvents(ctx, d.BizID, neededOrEvents)
			if status.Code != bizuserinters.StatusCodeOk {
				return
			}

			status.Code = bizuserinters.StatusCodeNeedAuthenticator

			return
		}
	}

	status = impl.tokenManager.ClearCurrentEvents(ctx, d.BizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}
