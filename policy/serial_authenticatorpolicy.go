package policy

import (
	"context"

	"github.com/sbasestarter/bizuserlib"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func NewSerialAuthenticatorPolicy(authenticatorEvents ...bizuserinters.AuthenticatorEvent) bizuserlib.Policy {
	return &serial2AuthenticatorPolicyImpl{
		authenticatorEvents: authenticatorEvents,
	}
}

type serial2AuthenticatorPolicyImpl struct {
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

			status.Code = bizuserinters.StatusCodeNeedAuthenticator

			return
		}
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}
