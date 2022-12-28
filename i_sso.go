package bizuserlib

type SSO interface {
	CheckJumpURL(ssoJumpURL string) bool
}
