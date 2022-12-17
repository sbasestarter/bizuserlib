package authenticator

import (
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/admin"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/google2fa"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/usermanager"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/userpass"
)

type DBModel interface {
	google2fa.DBModel
	userpass.DBModel
	usermanager.DBModel
	usermanager.APIModel

	admin.DBModel
}
