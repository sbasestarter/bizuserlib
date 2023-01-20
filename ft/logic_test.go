package ft

import (
	"context"
	"testing"

	"github.com/sbasestarter/bizuserlib"
	"github.com/sbasestarter/bizuserlib/authenticator/anonymous"
	"github.com/sbasestarter/bizuserlib/authenticator/google2fa"
	"github.com/sbasestarter/bizuserlib/authenticator/userpass"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	usertokenmanagerinter "github.com/sbasestarter/bizuserlib/bizuserinters/usertokenmanager"
	"github.com/sbasestarter/bizuserlib/impl/mongo/model/authenticator/model"
	"github.com/sbasestarter/bizuserlib/impl/redis/tokenmanager"
	usertokenmanagerredis "github.com/sbasestarter/bizuserlib/impl/redis/usertokenmanager"
	authenticatormodel "github.com/sbasestarter/bizuserlib/model/authenticator"
	modelmem "github.com/sbasestarter/bizuserlib/model/authenticator/model"
	"github.com/sbasestarter/bizuserlib/policy"
	"github.com/sbasestarter/bizuserlib/sso"
	tokenmanagermem "github.com/sbasestarter/bizuserlib/tokenmanager"
	usertokenmanagermem "github.com/sbasestarter/bizuserlib/usertokenmanager"
	authenticatorlib "github.com/sgostarter/libeasygo/authenticator"
	"github.com/sgostarter/libeasygo/stg/mongoex"
	"github.com/sgostarter/libeasygo/stg/redisex"
	"github.com/stretchr/testify/assert"
)

// nolint
func Test1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tokenManager := tokenmanagermem.NewMemoryTokenManager()

	//userTokenManager := usertokenmanagermem.NewMemoryUserTokenManager()
	userTokenManager := usertokenmanagermem.NewJWTUserTokenManager("x", usertokenmanagermem.NewMemoryJWTDataStorage())

	userPassGoogle2FARegisterPolicy := policy.NewSerialAuthenticatorPolicy(tokenManager, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.SetupEvent,
	}, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})
	userPassGoogle2FALoginPolicy := policy.NewSerialAuthenticatorPolicy(tokenManager, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.VerifyEvent,
	}, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})

	dbModel := modelmem.NewMemoryDBModel(tokenManager)
	userManagerModel := modelmem.NewUserManagerModel(dbModel)

	s := sso.NewCfgSSO([]string{"a.com", "b.com"})

	userManager := bizuserlib.NewUserManager(tokenManager, userTokenManager,
		userPassGoogle2FARegisterPolicy, userPassGoogle2FALoginPolicy, userPassGoogle2FALoginPolicy, userPassGoogle2FALoginPolicy,
		userManagerModel, dbModel, s, nil)

	bizID, neededOrAuthenticators, status := userManager.RegisterBegin(ctx, "")
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.SetupEvent,
	})

	tokenManagerModel := authenticatormodel.NewDirectTokenManagerModel(tokenManager)
	userPassModel := modelmem.NewUserPassModel(dbModel, tokenManagerModel)

	userPassAuthenticator := userpass.NewAuthenticator(userPassModel, "x")

	status = userPassAuthenticator.Register(ctx, bizID, "user1", "pass2")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.RegisterCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})

	cacheMode := authenticatormodel.NewMemoryCacheModel()
	google2FAModel := modelmem.NewGoogle2FAModel(dbModel, tokenManagerModel, cacheMode)
	google2FAAuthenticator := google2fa.NewAuthenticator(google2FAModel, "stw.com")

	secretKey, qrCode, status := google2FAAuthenticator.GetSetupInfo(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	t.Log("google2fa: ", secretKey, qrCode)

	code, err := authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.DoSetup(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.RegisterCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 0, len(neededOrAuthenticators))

	userID, token, _, status := userManager.RegisterEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.True(t, len(token.Token) > 0)
	assert.True(t, userID > 0)

	users, status := userManager.ListUsers(ctx, token.Token)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 1, len(users))
	assert.EqualValues(t, "user1", users[0].UserName)
	assert.EqualValues(t, true, users[0].HasGoogle2FA)

	_, _, tokenUserInfo, status := userManager.CheckToken(ctx, token.Token, "")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, "user1", tokenUserInfo.UserName)
	t.Log(tokenUserInfo.ID, tokenUserInfo.Expiration)

	//
	//
	//
	bizID, neededOrAuthenticators, status = userManager.LoginBegin(ctx, "")
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.VerifyEvent,
	})

	status = userPassAuthenticator.Login(ctx, bizID, "user1", "pass1")
	assert.EqualValues(t, bizuserinters.StatusCodeVerifyError, status.Code)

	status = userPassAuthenticator.Login(ctx, bizID, "user1", "pass2")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.LoginCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)

	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})

	code, err = authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.Verify(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.LoginCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 0, len(neededOrAuthenticators))

	userID, token, _, status = userManager.LoginEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.True(t, len(token.Token) > 0)
	assert.True(t, userID > 0)

	_, _, tokenUserInfo, status = userManager.CheckToken(ctx, token.Token, "")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, "user1", tokenUserInfo.UserName)
	t.Log(tokenUserInfo.ID, tokenUserInfo.Expiration)
}

func TestAnonymousAuthenticator(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tokenManager := tokenmanagermem.NewMemoryTokenManager()
	userTokenManager := usertokenmanagermem.NewMemoryUserTokenManager()
	anonymousRegisterPolicy := policy.NewSerialAuthenticatorPolicy(tokenManager, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorAnonymous,
		Event:         bizuserinters.SetupEvent,
	})
	anonymousLoginPolicy := policy.NewSerialAuthenticatorPolicy(tokenManager, bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorAnonymous,
		Event:         bizuserinters.VerifyEvent,
	})

	dbModel := modelmem.NewMemoryDBModel(tokenManager)
	userManagerModel := modelmem.NewUserManagerModel(dbModel)
	s := sso.NewCfgSSO([]string{"a.com", "b.com"})

	userManager := bizuserlib.NewUserManager(tokenManager, userTokenManager, anonymousRegisterPolicy, anonymousLoginPolicy,
		anonymousLoginPolicy, anonymousLoginPolicy, userManagerModel, dbModel, s, nil)

	bizID, neededOrAuthenticators, status := userManager.LoginBegin(ctx, "")
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorAnonymous,
		Event:         bizuserinters.VerifyEvent,
	})

	tokenManagerModel := authenticatormodel.NewDirectTokenManagerModel(tokenManager)
	anonymousAuthenticator := anonymous.NewAuthenticator(modelmem.NewAnonymousModel(tokenManagerModel))

	status = anonymousAuthenticator.SetUserName(ctx, bizID, "user1x")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.LoginCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 0, len(neededOrAuthenticators))

	userID, token, _, status := userManager.LoginEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.True(t, len(token.Token) > 0)
	assert.True(t, userID > 0)

	_, _, tokenUserInfo, status := userManager.CheckToken(ctx, token.Token, "")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, "user1x", tokenUserInfo.UserName)
	t.Log(tokenUserInfo.ID, tokenUserInfo.Expiration)
}

func TestConditionPolicy(t *testing.T) {
	tokenManager := tokenmanagermem.NewMemoryTokenManager()
	jwtDataStorage := usertokenmanagermem.NewMemoryJWTDataStorage()
	dbModel := modelmem.NewMemoryDBModel(tokenManager)
	conditionPolicyEx(t, tokenManager, jwtDataStorage, dbModel)
}

// nolint
func TestConditionPolicy2(t *testing.T) {
	redisCli, err := redisex.InitRedis("redis://:redis_default_pass@127.0.0.1:8300/0")
	assert.Nil(t, err)
	tokenManager := tokenmanager.NewRedisTokenManager(redisCli, "", nil)
	jwtDataStorage := usertokenmanagerredis.NewRedisJWTDataStorage(redisCli, nil)
	mongoCli, opts, err := mongoex.InitMongo("mongodb://mongo_default_user:mongo_default_pass@127.0.0.1:8309/my_db")
	assert.Nil(t, err)
	dbModel := model.NewMongoDBModel(mongoCli, opts.Auth.AuthSource, "ut_users", tokenManager, nil)
	mongoDBModel4UT, _ := dbModel.(model.MongoDBModel4UT)
	mongoDBModel4UT.Cleanup4UT()
	conditionPolicyEx(t, tokenManager, jwtDataStorage, dbModel)
}

// nolint
func conditionPolicyEx(t *testing.T, tokenManager bizuserinters.TokenManagerAll,
	jwtDataStorage usertokenmanagerinter.JWTDataStorage, dbModel authenticator.DBModel) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	userTokenManager := usertokenmanagermem.NewJWTUserTokenManager("x", jwtDataStorage)
	ply := policy.DefaultConditionAuthenticatorPolicy(tokenManager)

	userManagerModel := modelmem.NewUserManagerModel(dbModel)

	s := sso.NewCfgSSO([]string{"a.com", "b.com"})

	userManager := bizuserlib.NewUserManager(tokenManager, userTokenManager,
		ply, ply, ply, ply,
		userManagerModel, dbModel, s, nil)

	bizID, neededOrAuthenticators, status := userManager.RegisterBegin(ctx, "")
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.SetupEvent,
	})

	tokenManagerModel := authenticatormodel.NewDirectTokenManagerModel(tokenManager)
	userPassModel := modelmem.NewUserPassModel(dbModel, tokenManagerModel)

	userPassAuthenticator := userpass.NewAuthenticator(userPassModel, "x")

	status = userPassAuthenticator.Register(ctx, bizID, "user1", "pass2")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.RegisterCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})

	cacheMode := authenticatormodel.NewMemoryCacheModel()
	google2FAModel := modelmem.NewGoogle2FAModel(dbModel, tokenManagerModel, cacheMode)
	google2FAAuthenticator := google2fa.NewAuthenticator(google2FAModel, "stw.com")

	secretKey, qrCode, status := google2FAAuthenticator.GetSetupInfo(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	t.Log("google2fa: ", secretKey, qrCode)

	code, err := authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.DoSetup(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.RegisterCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 0, len(neededOrAuthenticators))

	userID, token, _, status := userManager.RegisterEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.True(t, len(token.Token) > 0)
	assert.True(t, userID > 0)

	users, status := userManager.ListUsers(ctx, token.Token)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 1, len(users))
	assert.EqualValues(t, "user1", users[0].UserName)
	assert.EqualValues(t, true, users[0].HasGoogle2FA)

	_, _, tokenUserInfo, status := userManager.CheckToken(ctx, token.Token, "")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, "user1", tokenUserInfo.UserName)
	t.Log(tokenUserInfo.ID, tokenUserInfo.Expiration)

	//
	//
	//

	bizID, neededOrAuthenticators, status = userManager.LoginBegin(ctx, "")
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.VerifyEvent,
	})

	status = userPassAuthenticator.Login(ctx, bizID, "user1", "pass1")
	assert.EqualValues(t, bizuserinters.StatusCodeVerifyError, status.Code)

	status = userPassAuthenticator.Login(ctx, bizID, "user1", "pass2")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.LoginCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)

	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})

	code, err = authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.Verify(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.LoginCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, 0, len(neededOrAuthenticators))

	userID, token, _, status = userManager.LoginEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.True(t, len(token.Token) > 0)
	assert.True(t, userID > 0)

	_, _, tokenUserInfo, status = userManager.CheckToken(ctx, token.Token, "")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, "user1", tokenUserInfo.UserName)
	t.Log(tokenUserInfo.ID, tokenUserInfo.Expiration)

	//
	//
	//

	bizID, neededOrAuthenticators, status = userManager.ChangeBegin(ctx, token.Token,
		[]bizuserinters.AuthenticatorIdentity{bizuserinters.AuthenticatorUserPassPass})
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.VerifyEvent,
	})

	neededOrAuthenticators, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.VerifyEvent,
	})

	status = userPassAuthenticator.VerifyPassword(ctx, bizID, "pass2")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.SetupEvent,
	})

	status = userPassAuthenticator.ChangePassword(ctx, bizID, "pass3")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	_, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	status = userManager.ChangeEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	//
	//
	//

	bizID, neededOrAuthenticators, status = userManager.ChangeBegin(ctx, token.Token,
		[]bizuserinters.AuthenticatorIdentity{bizuserinters.AuthenticatorGoogle2FA})
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) == 2)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.VerifyEvent,
	})
	assert.EqualValues(t, neededOrAuthenticators[1], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})

	status = userPassAuthenticator.Login(ctx, bizID, "user1", "pass3")
	assert.EqualValues(t, bizuserinters.StatusCodeNoDataError, status.Code)

	status = userPassAuthenticator.VerifyPassword(ctx, bizID, "pass3")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})

	secretKey, qrCode, status = google2FAAuthenticator.GetSetupInfo(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	t.Log("google2fa: ", secretKey, qrCode)

	code, err = authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.DoSetup(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	_, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	status = userManager.ChangeEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	//
	//
	//

	bizID, neededOrAuthenticators, status = userManager.ChangeBegin(ctx, token.Token,
		[]bizuserinters.AuthenticatorIdentity{bizuserinters.AuthenticatorGoogle2FA})
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) == 2)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.VerifyEvent,
	})
	assert.EqualValues(t, neededOrAuthenticators[1], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})

	code, err = authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.Verify(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	neededOrAuthenticators, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) > 0)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.SetupEvent,
	})

	secretKey, qrCode, status = google2FAAuthenticator.GetSetupInfo(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	t.Log("google2fa: ", secretKey, qrCode)

	code, err = authenticatorlib.MakeGoogleAuthenticatorForNow(secretKey)
	assert.Nil(t, err)

	status = google2FAAuthenticator.DoSetup(ctx, bizID, code)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	_, status = userManager.ChangeCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	status = userManager.ChangeEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	bizID, neededOrAuthenticators, status = userManager.DeleteBegin(ctx, token.Token,
		[]bizuserinters.AuthenticatorIdentity{bizuserinters.AuthenticatorGoogle2FA})
	assert.EqualValues(t, bizuserinters.StatusCodeNeedAuthenticator, status.Code)
	assert.True(t, len(bizID) > 0)
	assert.True(t, len(neededOrAuthenticators) == 2)
	assert.EqualValues(t, neededOrAuthenticators[0], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPassPass,
		Event:         bizuserinters.VerifyEvent,
	})
	assert.EqualValues(t, neededOrAuthenticators[1], bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.VerifyEvent,
	})

	status = userPassAuthenticator.VerifyPassword(ctx, bizID, "pass3")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	_, status = userManager.DeleteCheck(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)

	status = userManager.DeleteEnd(ctx, bizID)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
}
