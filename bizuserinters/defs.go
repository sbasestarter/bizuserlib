package bizuserinters

type AuthenticatorIdentity string

const (
	AuthenticatorUser AuthenticatorIdentity = "__user"

	AuthenticatorAnonymous    AuthenticatorIdentity = "_anonymous"
	AuthenticatorUserPass     AuthenticatorIdentity = "_user-pass"
	AuthenticatorUserPassPass AuthenticatorIdentity = "_user-pass-pass"
	AuthenticatorPhone        AuthenticatorIdentity = "_phone"
	AuthenticatorEmail        AuthenticatorIdentity = "_email"
	AuthenticatorGoogle2FA    AuthenticatorIdentity = "_google-2fa"

	AuthenticatorAdmin     AuthenticatorIdentity = "_admin"
	AuthenticatorAdminFlag AuthenticatorIdentity = "_admin-flag"
)

type Event int

const (
	SetupEvent Event = iota
	VerifyEvent
	ChangeEvent
	DeleteEvent
)

type AuthenticatorEvent struct {
	Authenticator AuthenticatorIdentity
	Event         Event
}

func (e AuthenticatorEvent) Equal(other AuthenticatorEvent) bool {
	return e.Event == other.Event && e.Authenticator == other.Authenticator
}

const (
	DeleteFieldUser      = 0x0001
	DeleteFieldGoogle2FA = 0x0002
)
