package usertokenmanager

import (
	"context"
	"time"
)

type JWTDataStorage interface {
	Record(ctx context.Context, key string, expiration time.Duration) error
	Exists(ctx context.Context, key string) (t bool, err error)
}
