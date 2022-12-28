package usertokenmanager

import (
	"context"
	"crypto/md5" // nolint: gosec
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/usertokenmanager"
	"github.com/sgostarter/i/commerr"
)

const (
	defaultTokenExpiration = time.Hour * 24 * 31 * 12
)

func NewJWTUserTokenManager(tokenSecKey string, storage usertokenmanager.JWTDataStorage) bizuserinters.UserTokenManager {
	if storage == nil {
		return nil
	}

	h := md5.Sum([]byte(tokenSecKey)) // nolint: gosec

	return &jwtUserTokenManagerImpl{
		tokenSecKey: h[:],
		storage:     storage,
	}
}

type jwtUserTokenManagerImpl struct {
	tokenSecKey interface{}
	storage     usertokenmanager.JWTDataStorage
}

type UserClaims struct {
	bizuserinters.UserTokenInfo
	jwt.StandardClaims
}

type SSOClaims struct {
	Token string
	jwt.StandardClaims
}

func (impl *jwtUserTokenManagerImpl) GenToken(ctx context.Context, userInfo *bizuserinters.UserTokenInfo) (
	token string, status bizuserinters.Status) {
	if userInfo == nil || (userInfo.ID == 0 && userInfo.UserName == "") {
		status = bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeInvalidArgsError)

		return
	}

	token, err := impl.generateToken(userInfo)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *jwtUserTokenManagerImpl) DeleteToken(ctx context.Context, token string) bizuserinters.Status {
	if impl.hasTokenDeleted(ctx, token) {
		return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeExpiredError)
	}

	_, expireAt, err := impl.parseToken(token)
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)
	}

	extendDuration := time.Duration(expireAt - time.Now().Unix())
	if extendDuration <= 0 {
		extendDuration = time.Second
	}

	impl.deleteToken(ctx, token, extendDuration)

	return bizuserinters.MakeSuccessStatus()
}

func (impl *jwtUserTokenManagerImpl) ExplainToken(ctx context.Context, token string) (
	userInfo *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	if impl.hasTokenDeleted(ctx, token) {
		status = bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeExpiredError)

		return
	}

	userInfo, _, err := impl.parseToken(token)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)

		return
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *jwtUserTokenManagerImpl) RenewToken(ctx context.Context, token string) (
	newToken string, userInfo *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	if impl.hasTokenDeleted(ctx, token) {
		status = bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeExpiredError)

		return
	}

	userInfo, _, err := impl.parseToken(token)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)

		return
	}

	newToken, err = impl.generateToken(userInfo)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	impl.deleteToken(ctx, token, time.Minute)

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *jwtUserTokenManagerImpl) GenSSOToken(ctx context.Context, parentToken string,
	expiration time.Duration) (token string, status bizuserinters.Status) {
	_, status = impl.ExplainToken(ctx, parentToken)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	token, err := impl.generateSSOToken(SSOClaims{
		Token: parentToken,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiration).Unix(),
		},
	})
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *jwtUserTokenManagerImpl) ExplainSSOToken(ctx context.Context, token string) (userInfo *bizuserinters.UserTokenInfo, status bizuserinters.Status) {
	if impl.hasTokenDeleted(ctx, token) {
		status = bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeExpiredError)

		return
	}

	parentToken, err := impl.parseSSOToken(token)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)

		return
	}

	userInfo, status = impl.ExplainToken(ctx, parentToken)

	return
}

//
//
//

func (impl *jwtUserTokenManagerImpl) generateToken(userInfo *bizuserinters.UserTokenInfo) (token string, err error) {
	userInfo.StartAt = time.Now()

	if userInfo.Expiration <= 0 {
		userInfo.Expiration = defaultTokenExpiration
	}

	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		UserTokenInfo: *userInfo,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(userInfo.Expiration).Unix(),
		},
	}).SignedString(impl.tokenSecKey)

	return
}

func (impl *jwtUserTokenManagerImpl) generateSSOToken(c SSOClaims) (token string, err error) {
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(impl.tokenSecKey)

	return
}

func (impl *jwtUserTokenManagerImpl) parseToken(token string) (userInfo *bizuserinters.UserTokenInfo, expireAt int64, err error) {
	var claims UserClaims

	tokenObj, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return impl.tokenSecKey, nil
	})
	if err != nil {
		return
	}

	if userClaims, ok := tokenObj.Claims.(*UserClaims); ok && tokenObj.Valid {
		userInfo = &userClaims.UserTokenInfo
		expireAt = userClaims.ExpiresAt
	} else {
		err = commerr.ErrUnauthenticated
	}

	return
}

func (impl *jwtUserTokenManagerImpl) parseSSOToken(token string) (parentToken string, err error) {
	var claims UserClaims

	tokenObj, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return impl.tokenSecKey, nil
	})
	if err != nil {
		return
	}

	if c, ok := tokenObj.Claims.(*SSOClaims); ok && tokenObj.Valid {
		parentToken = c.Token
	} else {
		err = commerr.ErrUnauthenticated
	}

	return
}

func (impl *jwtUserTokenManagerImpl) deleteToken(ctx context.Context, token string, extendDuration time.Duration) {
	_ = impl.storage.Record(ctx, token, extendDuration)
}

func (impl *jwtUserTokenManagerImpl) hasTokenDeleted(ctx context.Context, token string) bool {
	t, err := impl.storage.Exists(ctx, token)

	return err == nil && t
}
