package authenticator

import (
	"context"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type CacheModel interface {
	Set(ctx context.Context, key string, val interface{}) (status bizuserinters.Status)
	Get(ctx context.Context, key string) (val interface{}, status bizuserinters.Status)
	Del(ctx context.Context, key string) (status bizuserinters.Status)
}
