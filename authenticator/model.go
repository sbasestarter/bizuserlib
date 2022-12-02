package authenticator

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type Model interface {
	CheckVerifyEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status)
	CheckRegisterEventCompleted(ctx context.Context, bizID string) (status bizuserinters.Status)
}
