package google2fa

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type DBModel interface {
	GetGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status)
}
