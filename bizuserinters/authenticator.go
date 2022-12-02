package bizuserinters

import "context"

type Authenticator interface {
	VerifyCheck(ctx context.Context, bizID string) (status Status)
	RegisterCheck(ctx context.Context, bizID string) (status Status)
}
