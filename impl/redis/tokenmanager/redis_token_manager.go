package tokenmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/i/l"
)

const (
	completedAuthenticatorEventKeyPrefix = "completed_e:"
	authenticationDataKeyPrefix          = "ad:"
	currentUserInfoSubKey                = "cu"
	workDataSubKeyPrefix                 = "wd:"
	currentEventsSubKey                  = "ce"
)

func NewRedisTokenManager(redisCli *redis.Client, prefixKey string, logger l.Wrapper) bizuserinters.TokenManagerAll {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if redisCli == nil {
		logger.Error("no redis client")

		return nil
	}

	return &tokenManagerImpl{
		redisCli:  redisCli,
		prefixKey: prefixKey,
		logger:    logger.WithFields(l.StringField(l.ClsKey, "tokenManagerImpl")),
	}
}

type tokenManagerImpl struct {
	redisCli  *redis.Client
	prefixKey string
	logger    l.Wrapper
}

func (impl *tokenManagerImpl) GetCurrentEvents(ctx context.Context, bizID string) (es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	d, err := impl.redisCli.HGet(ctx, impl.tokenKey(bizID), currentEventsSubKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			status.Code = bizuserinters.StatusCodeNoDataError
		} else {
			status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
		}

		return
	}

	if len(d) == 0 {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	err = json.Unmarshal(d, &es)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeBadDataError, err)

		return
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *tokenManagerImpl) SetCurrentEvents(ctx context.Context, bizID string, es []bizuserinters.AuthenticatorEvent) bizuserinters.Status {
	d, err := json.Marshal(es)
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)
	}

	redisKey := impl.tokenKey(bizID)

	n, err := impl.redisCli.Exists(ctx, redisKey).Result()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	if n <= 0 {
		return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeNoDataError)
	}

	err = impl.redisCli.HSet(ctx, redisKey, currentEventsSubKey, d).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *tokenManagerImpl) ClearCurrentEvents(ctx context.Context, bizID string) bizuserinters.Status {
	if err := impl.redisCli.HDel(ctx, impl.tokenKey(bizID), currentEventsSubKey).Err(); err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *tokenManagerImpl) SetWorkData(ctx context.Context, bizID string, key string, d []byte) bizuserinters.Status {
	redisKey := impl.tokenKey(bizID)

	n, err := impl.redisCli.Exists(ctx, redisKey).Result()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	if n <= 0 {
		return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeNoDataError)
	}

	err = impl.redisCli.HSet(ctx, redisKey, impl.workDataSubKey(key), d).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *tokenManagerImpl) GetWorkData(ctx context.Context, bizID string, key string) (d []byte, status bizuserinters.Status) {
	d, err := impl.redisCli.HGet(ctx, impl.tokenKey(bizID), impl.workDataSubKey(key)).Bytes()
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeNoDataError, err)

		return
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *tokenManagerImpl) CreateToken(ctx context.Context) (bizID string, status bizuserinters.Status) {
	bizID = strconv.FormatUint(snowflake.ID(), 26)

	redisKey := impl.tokenKey(bizID)

	if err := impl.redisCli.HSet(ctx, redisKey, "created_at", time.Now()).Err(); err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	if err := impl.redisCli.ExpireAt(ctx, redisKey, time.Now().Add(time.Minute*10)).Err(); err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		impl.redisCli.Del(context.TODO(), redisKey) // FIXME

		return
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *tokenManagerImpl) DeleteToken(bizID string) {
	impl.redisCli.Del(context.TODO(), impl.tokenKey(bizID))
}

func (impl *tokenManagerImpl) MarkAuthenticatorEventCompleted(ctx context.Context, bizID string,
	e bizuserinters.AuthenticatorEvent) bizuserinters.Status {
	redisKey := impl.tokenKey(bizID)

	n, err := impl.redisCli.Exists(ctx, redisKey).Result()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	if n <= 0 {
		return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeNoDataError)
	}

	err = impl.redisCli.HSet(ctx, redisKey, impl.completedAuthenticatorEventSubKey(e), time.Now().Unix()).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *tokenManagerImpl) HasAuthenticatorEventCompleted(ctx context.Context, bizID string,
	e bizuserinters.AuthenticatorEvent) bizuserinters.Status {
	exists, err := impl.redisCli.HExists(ctx, impl.tokenKey(bizID), impl.completedAuthenticatorEventSubKey(e)).Result()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	if exists {
		return bizuserinters.MakeSuccessStatus()
	}

	return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeNotCompleted)
}

func (impl *tokenManagerImpl) GetAllCompletedAuthenticatorEvents(ctx context.Context, bizID string) (
	es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	ks, err := impl.redisCli.HGetAll(ctx, impl.tokenKey(bizID)).Result()
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	for k := range ks {
		if !impl.isCompletedAuthenticatorEventSubKey(k) {
			continue
		}

		e, ok := impl.parseCompletedAuthenticatorEventSubKey(k)
		if !ok {
			impl.logger.WithFields(l.ErrorField(err), l.StringField("k", k)).Error("invalidCompletedAuthenticatorEventSubKey")

			continue
		}

		es = append(es, e)
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *tokenManagerImpl) SetAuthenticatorData(ctx context.Context, bizID string,
	e bizuserinters.AuthenticatorEvent, ds map[string]interface{}) bizuserinters.Status {
	d, err := json.Marshal(ds)
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)
	}

	err = impl.redisCli.HSet(ctx, impl.tokenKey(bizID), impl.authenticatorDataSubKey(e), d).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *tokenManagerImpl) GetAllAuthenticatorDatas(ctx context.Context, bizID string,
	e bizuserinters.Event) (ds map[bizuserinters.AuthenticatorIdentity]map[string]interface{},
	status bizuserinters.Status) {
	ks, err := impl.redisCli.HGetAll(ctx, impl.tokenKey(bizID)).Result()
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	ds = make(map[bizuserinters.AuthenticatorIdentity]map[string]interface{})

	for k, d := range ks {
		if !impl.isAuthenticatorDataSubKey(k) {
			continue
		}

		de, ok := impl.parseAuthenticatorDataSubKey(k)
		if !ok {
			impl.logger.WithFields(l.ErrorField(err), l.StringField("k", k)).Error("invalidAuthenticatorDataSubKey")

			continue
		}

		if de.Event != e {
			continue
		}

		var m map[string]interface{}

		err = json.Unmarshal([]byte(d), &m)
		if err != nil {
			impl.logger.WithFields(l.ErrorField(err)).Error("unmarshalError")

			continue
		}

		ds[de.Authenticator] = m
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *tokenManagerImpl) SetCurrentUserInfo(ctx context.Context, bizID string, ui *bizuserinters.UserIdentity) bizuserinters.Status {
	d, err := json.Marshal(ui)
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInvalidArgsError, err)
	}

	err = impl.redisCli.HSet(ctx, impl.tokenKey(bizID), currentUserInfoSubKey, d).Err()
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *tokenManagerImpl) GetCurrentUserInfo(ctx context.Context, bizID string) (ui *bizuserinters.UserIdentity, status bizuserinters.Status) {
	d, err := impl.redisCli.HGet(ctx, impl.tokenKey(bizID), currentUserInfoSubKey).Bytes()
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	var userIdentity bizuserinters.UserIdentity

	err = json.Unmarshal(d, &userIdentity)
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	ui = &userIdentity
	status = bizuserinters.MakeSuccessStatus()

	return
}

//
//
//

func (impl *tokenManagerImpl) tokenKey(bizID string) string {
	return impl.prefixKey + "token:" + bizID
}

func (impl *tokenManagerImpl) completedAuthenticatorEventSubKey(e bizuserinters.AuthenticatorEvent) string {
	return impl.prefixKey + fmt.Sprintf("%s%d:%s", completedAuthenticatorEventKeyPrefix, e.Event, e.Authenticator)
}

func (impl *tokenManagerImpl) parseCompletedAuthenticatorEventSubKey(s string) (e bizuserinters.AuthenticatorEvent, ok bool) {
	if !strings.HasPrefix(s, impl.prefixKey+completedAuthenticatorEventKeyPrefix) {
		return
	}

	ps := strings.Split(s[len(impl.prefixKey+completedAuthenticatorEventKeyPrefix):], ":")
	if len(ps) != 2 {
		return
	}

	switch ps[0] {
	case "0":
		e.Event = bizuserinters.SetupEvent
	case "1":
		e.Event = bizuserinters.VerifyEvent
	case "2":
		e.Event = bizuserinters.ChangeEvent
	case "3":
		e.Event = bizuserinters.DeleteEvent
	default:
		return
	}

	e.Authenticator = bizuserinters.AuthenticatorIdentity(ps[1])

	ok = true

	return
}

func (impl *tokenManagerImpl) isCompletedAuthenticatorEventSubKey(s string) bool {
	return strings.HasPrefix(s, impl.prefixKey+completedAuthenticatorEventKeyPrefix)
}

func (impl *tokenManagerImpl) authenticatorDataSubKey(e bizuserinters.AuthenticatorEvent) string {
	return impl.prefixKey + fmt.Sprintf("%s%d:%s", authenticationDataKeyPrefix, e.Event, e.Authenticator)
}

func (impl *tokenManagerImpl) parseAuthenticatorDataSubKey(s string) (e bizuserinters.AuthenticatorEvent, ok bool) {
	if !strings.HasPrefix(s, impl.prefixKey+authenticationDataKeyPrefix) {
		return
	}

	ps := strings.Split(s[len(impl.prefixKey+authenticationDataKeyPrefix):], ":")
	if len(ps) != 2 {
		return
	}

	switch ps[0] {
	case "0":
		e.Event = bizuserinters.SetupEvent
	case "1":
		e.Event = bizuserinters.VerifyEvent
	default:
		return
	}

	e.Authenticator = bizuserinters.AuthenticatorIdentity(ps[1])

	ok = true

	return
}

func (impl *tokenManagerImpl) isAuthenticatorDataSubKey(s string) bool {
	return strings.HasPrefix(s, impl.prefixKey+authenticationDataKeyPrefix)
}

func (impl *tokenManagerImpl) workDataSubKey(key string) string {
	return impl.prefixKey + fmt.Sprintf("%s%s", workDataSubKeyPrefix, key)
}
