package model

import (
	"context"
	"time"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator/usermanager"
	"github.com/sgostarter/i/l"
	"github.com/sgostarter/libeasygo/stg/mongoex"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBModel4UT interface {
	Cleanup4UT()
}

func NewMongoDBModel(mongoCli *mongo.Client, mongoDB, collectionName string, tokenManager bizuserinters.TokenManager,
	logger l.Wrapper) authenticator.DBModel {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if mongoCli == nil {
		logger.Error("no mongo client")

		return nil
	}

	if mongoDB == "" {
		logger.Error("no mongo db")

		return nil
	}

	if collectionName == "" {
		logger.Error("no mongo collection name")

		return nil
	}

	if tokenManager == nil {
		logger.Error("no token manager")

		return nil
	}

	impl := &dbModelImpl{
		mongoCli:       mongoCli,
		mongoDB:        mongoDB,
		collectionName: collectionName,
		tokenManager:   tokenManager,
		logger:         logger.WithFields(l.StringField(l.ClsKey, "dbModelImpl")),
	}

	impl.init()

	return impl
}

type dbModelImpl struct {
	mongoCli       *mongo.Client
	mongoDB        string
	collectionName string
	db             *mongo.Database
	collection     *mongo.Collection
	tokenManager   bizuserinters.TokenManager
	logger         l.Wrapper
}

func (impl *dbModelImpl) init() {
	impl.db = impl.mongoCli.Database(impl.mongoDB)
	impl.collection = impl.db.Collection(impl.collectionName)

	if _, err := impl.collection.Indexes().CreateOne(context.TODO(), mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_name", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("CreateUniqueIndexFailed")
	}
}

func (impl *dbModelImpl) GetUserPassInfo(ctx context.Context, bizID string) (userID uint64, userName, password string, status bizuserinters.Status) {
	userInfo, status := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if userInfo.ID == 0 {
		status = bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeNoDataError)

		return
	}

	var u User
	if err := impl.collection.FindOne(ctx,
		bson.M{
			"_id": userInfo.ID,
		}).Decode(&u); err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("MongoFindFailed")

		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	userID = userInfo.ID
	userName = u.UserName
	password = u.Password

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *dbModelImpl) UpdateUser(ctx context.Context, userInfo *bizuserinters.UserInfoInner) (status bizuserinters.Status) {
	if userInfo == nil || userInfo.ID == 0 {
		return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeInvalidArgsError)
	}

	update := bson.M{}

	if userInfo.UserName != "" {
		update["user_name"] = userInfo.UserName
	}

	if userInfo.Password != "" {
		update["password"] = userInfo.Password
	}

	if userInfo.Google2FASecretKey != "" {
		update["google_2_fa"] = userInfo.Google2FASecretKey
	}

	if err := impl.collection.FindOneAndUpdate(ctx, bson.M{
		"_id": userInfo.ID,
	}, bson.M{
		"$set": update,
	}).Err(); err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	return bizuserinters.MakeSuccessStatus()
}

func (impl *dbModelImpl) Delete(ctx context.Context, userID uint64, fields uint64) (status bizuserinters.Status) {
	if fields&usermanager.DeleteFieldUser == usermanager.DeleteFieldUser {
		_, err := impl.collection.DeleteOne(ctx, bson.M{"_id": userID})
		if err != nil {
			return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeOk, err)
		}

		return bizuserinters.MakeSuccessStatus()
	}

	if fields&usermanager.DeleteFieldGoogle2FA == usermanager.DeleteFieldGoogle2FA {
		if err := impl.collection.FindOneAndUpdate(ctx, bson.M{
			"_id": userID,
		}, bson.M{
			"$set": bson.M{
				"google_2_fa": "",
			},
		}).Err(); err != nil {
			return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
		}

		return bizuserinters.MakeSuccessStatus()
	}

	return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeInvalidArgsError)
}

func (impl *dbModelImpl) GetGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status) {
	userInfo, status := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	var u User
	if err := impl.collection.FindOne(ctx,
		bson.M{
			"_id": userInfo.ID,
		}).Decode(&u); err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("MongoFindFailed")

		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	secretKey = u.Google2FA

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *dbModelImpl) GetUserPassInfoByUserName(ctx context.Context, _ string, userName string) (userID uint64, password string, status bizuserinters.Status) {
	var u User
	if err := impl.collection.FindOne(ctx,
		bson.M{
			"user_name": userName,
		}).Decode(&u); err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("MongoFindFailed")

		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	userID = u.ID
	password = u.Password

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *dbModelImpl) AddUser(ctx context.Context, userInfo *bizuserinters.UserInfoInner) bizuserinters.Status {
	id, err := mongoex.GetDataID(ctx, impl.mongoCli.Database(impl.mongoDB), impl.collectionName)
	if err != nil {
		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	u := &User{
		ID:        id,
		UserName:  userInfo.UserName,
		Password:  userInfo.Password,
		Google2FA: userInfo.Google2FASecretKey,
		CreateAt:  time.Now().Unix(),
	}
	_, err = impl.collection.InsertOne(ctx, u)

	if err != nil {
		if mongoErr, ok := err.(mongo.WriteException); ok {
			if mongoErr.HasErrorCode(11000) {
				return bizuserinters.MakeStatusByCode(bizuserinters.StatusCodeDupError)
			}
		}

		return bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)
	}

	userInfo.ID = id

	return bizuserinters.MakeSuccessStatus()
}

func (impl *dbModelImpl) ListUsers(ctx context.Context) (users []*bizuserinters.UserInfo, status bizuserinters.Status) {
	cursor, err := impl.collection.Find(ctx, bson.D{})
	if err != nil {
		status = bizuserinters.MakeStatusByError(bizuserinters.StatusCodeInternalError, err)

		return
	}

	var us []*User

	err = cursor.All(ctx, &us)
	if err != nil {
		return
	}

	for _, u := range us {
		users = append(users, &bizuserinters.UserInfo{
			ID:           u.ID,
			UserName:     u.UserName,
			HasGoogle2FA: u.Google2FA != "",
		})
	}

	status = bizuserinters.MakeSuccessStatus()

	return
}

func (impl *dbModelImpl) Cleanup4UT() {
	_ = impl.collection.Drop(context.Background())
	impl.init()
}
