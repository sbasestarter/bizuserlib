package model

import (
	"context"
	"strconv"
	"testing"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/libeasygo/stg/mongoex"
	"github.com/stretchr/testify/assert"
)

type utTokenManger struct {
}

func (impl *utTokenManger) GetCurrentEvents(ctx context.Context, bizID string) (es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) SetWorkData(ctx context.Context, bizID string, key string, d []byte) (status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) GetWorkData(ctx context.Context, bizID string, key string) (d []byte, status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) CreateToken(ctx context.Context) (bizID string, status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) DeleteToken(bizID string) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) MarkAuthenticatorEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) bizuserinters.Status {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) HasAuthenticatorEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) GetAllCompletedAuthenticatorEvents(ctx context.Context, bizID string) (es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) SetAuthenticatorData(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent, ds map[string]interface{}) (status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) GetAllAuthenticatorDatas(ctx context.Context, bizID string, e bizuserinters.Event) (ds map[bizuserinters.AuthenticatorIdentity]map[string]interface{}, status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) SetCurrentUserInfo(ctx context.Context, bizID string, ui *bizuserinters.UserIdentity) (status bizuserinters.Status) {
	//TODO implement me
	panic("implement me")
}

func (impl *utTokenManger) GetCurrentUserInfo(ctx context.Context, bizID string) (ui *bizuserinters.UserIdentity, status bizuserinters.Status) {
	id, _ := strconv.ParseUint(bizID, 10, 64)

	ui = &bizuserinters.UserIdentity{ID: id}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func New() bizuserinters.TokenManager {
	return &utTokenManger{}
}

// nolint
func Test1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, opts, err := mongoex.InitMongo("mongodb://mongo_default_user:mongo_default_pass@127.0.0.1:8309/my_db")
	assert.Nil(t, err)

	m := NewMongoDBModel(cli, opts.Auth.AuthSource, "users", New(), nil)
	rm, ok := m.(*dbModelImpl)
	assert.True(t, ok)

	_ = rm.collection.Drop(context.TODO())
	_ = rm.db.Collection("ids").Drop(context.TODO())

	m = NewMongoDBModel(cli, opts.Auth.AuthSource, "users", New(), nil)

	u := &bizuserinters.UserInfoInner{
		UserIdentity: bizuserinters.UserIdentity{
			ID:       0,
			UserName: "user1",
		},
		Password: "pass1",
	}
	status := m.AddUser(ctx, u)
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.True(t, u.ID > 0)

	status = m.AddUser(ctx, &bizuserinters.UserInfoInner{
		UserIdentity: bizuserinters.UserIdentity{
			ID:       0,
			UserName: "user1",
		},
		Password: "user2",
	})
	assert.EqualValues(t, bizuserinters.StatusCodeDupError, status.Code)

	userID, password, status := m.GetUserPassInfoByUserName(ctx, "1", "user1")
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, u.ID, userID)
	assert.EqualValues(t, "pass1", password)

	secretKey, status := m.GetGoogle2FASecretKey(ctx, strconv.FormatUint(u.ID, 10))
	assert.EqualValues(t, bizuserinters.StatusCodeOk, status.Code)
	assert.EqualValues(t, "", secretKey)
}
