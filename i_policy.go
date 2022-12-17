package bizuserlib

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type CheckPolicyData struct {
	BizID      string
	Purpose    bizuserinters.AuthenticatorEvent
	DoneEvents []bizuserinters.AuthenticatorEvent
}

type Policy interface {
	Check(ctx context.Context, d CheckPolicyData) (neededOrEvents []bizuserinters.AuthenticatorEvent,
		status bizuserinters.Status)
}
