package bizuserinters

type AuthenticatorIdentity string

const (
	AuthenticatorUser AuthenticatorIdentity = "__user"

	AuthenticatorAnonymous AuthenticatorIdentity = "_anonymous"
	AuthenticatorUserPass  AuthenticatorIdentity = "_user-pass"
	AuthenticatorPhone     AuthenticatorIdentity = "_phone"
	AuthenticatorEmail     AuthenticatorIdentity = "_email"
	AuthenticatorGoogle2FA AuthenticatorIdentity = "_google-2fa"
	AuthenticatorToken     AuthenticatorIdentity = "_token"
)

type Event int

const (
	RegisterEvent Event = iota
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
