package model

import (
	"context"
	"sync"

	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
)

func NewMemoryDBModel(tokenManager bizuserinters.TokenManager) authenticator.DBModel {
	if tokenManager == nil {
		return nil
	}

	return &memoryDBModelImpl{
		tokenManager: tokenManager,
		users:        make(map[uint64]*userData),
		name2UserIDs: make(map[string]uint64),
	}
}

type userData struct {
	userName        string
	password        string
	google2faSecret string
	adminFlag       bool
}

type memoryDBModelImpl struct {
	tokenManager bizuserinters.TokenManager

	lock         sync.Mutex
	users        map[uint64]*userData
	name2UserIDs map[string]uint64
}

func (impl *memoryDBModelImpl) IsAdmin(ctx context.Context, bizID string) (adminFlag bool, status bizuserinters.Status) {
	ui, status := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if ui.ID == 0 {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	impl.lock.Lock()
	defer impl.lock.Unlock()

	u, ok := impl.users[ui.ID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	adminFlag = u.adminFlag

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryDBModelImpl) GetUserPassInfo(ctx context.Context, bizID string) (userID uint64, userName, password string, status bizuserinters.Status) {
	ui, status := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	if ui.ID == 0 {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	impl.lock.Lock()
	defer impl.lock.Unlock()

	u, ok := impl.users[ui.ID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	userID = ui.ID
	userName = u.userName
	password = u.password

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryDBModelImpl) ListUsers(ctx context.Context) (users []*bizuserinters.UserInfo, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	for u, data := range impl.users {
		users = append(users, &bizuserinters.UserInfo{
			ID:           u,
			UserName:     data.userName,
			HasGoogle2FA: len(data.google2faSecret) > 0,
			Admin:        data.adminFlag,
		})
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryDBModelImpl) GetGoogle2FASecretKey(ctx context.Context, bizID string) (secretKey string, status bizuserinters.Status) {
	userInfo, status := impl.tokenManager.GetCurrentUserInfo(ctx, bizID)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	impl.lock.Lock()
	defer impl.lock.Unlock()

	u, ok := impl.users[userInfo.ID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	secretKey = u.google2faSecret
	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryDBModelImpl) GetUserPassInfoByUserName(ctx context.Context, bizID string, userName string) (userID uint64, password string, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	userID, ok := impl.name2UserIDs[userName]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	u, ok := impl.users[userID]
	if !ok {
		status.Code = bizuserinters.StatusCodeInternalError

		return
	}

	password = u.password
	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryDBModelImpl) Delete(ctx context.Context, userID uint64, fields uint64) (status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	dbUser, ok := impl.users[userID]
	if !ok {
		status.Code = bizuserinters.StatusCodeExistsError

		return
	}

	if fields&bizuserinters.DeleteFieldUser == bizuserinters.DeleteFieldUser {
		delete(impl.users, userID)
		delete(impl.name2UserIDs, dbUser.userName)

		status.Code = bizuserinters.StatusCodeOk

		return
	}

	if fields&bizuserinters.DeleteFieldGoogle2FA == bizuserinters.DeleteFieldGoogle2FA {
		dbUser.google2faSecret = ""

		status.Code = bizuserinters.StatusCodeOk

		return
	}

	status.Code = bizuserinters.StatusCodeInvalidArgsError

	return
}

func (impl *memoryDBModelImpl) UpdateUser(ctx context.Context, userInfo *bizuserinters.UserInfoInner) (status bizuserinters.Status) {
	if userInfo == nil || userInfo.ID == 0 {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	impl.lock.Lock()
	defer impl.lock.Unlock()

	dbUser, ok := impl.users[userInfo.ID]
	if !ok {
		status.Code = bizuserinters.StatusCodeExistsError

		return
	}

	if userInfo.UserName != "" && userInfo.UserName != dbUser.userName {
		if _, ok = impl.name2UserIDs[userInfo.UserName]; ok {
			status.Code = bizuserinters.StatusCodeDupError

			return
		}

		delete(impl.name2UserIDs, dbUser.userName)

		dbUser.userName = userInfo.UserName
		impl.name2UserIDs[dbUser.userName] = userInfo.ID
	}

	if userInfo.Password != "" && userInfo.Password != dbUser.password {
		dbUser.password = userInfo.Password
	}

	if userInfo.Google2FASecretKey != "" && userInfo.Google2FASecretKey != dbUser.google2faSecret {
		dbUser.google2faSecret = userInfo.Google2FASecretKey
	}

	for _, flag := range userInfo.AdminFlags {
		if flag.UserID == 0 {
			continue
		}

		if _, exists := impl.users[flag.UserID]; exists {
			impl.users[flag.UserID].adminFlag = flag.Flag
		}
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *memoryDBModelImpl) AddUser(ctx context.Context, userInfo *bizuserinters.UserInfoInner) (status bizuserinters.Status) {
	if userInfo == nil || userInfo.UserName == "" {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	impl.lock.Lock()
	defer impl.lock.Unlock()

	if _, ok := impl.name2UserIDs[userInfo.UserName]; ok {
		status.Code = bizuserinters.StatusCodeExistsError

		return
	}

	userInfo.ID = snowflake.ID()
	impl.users[userInfo.ID] = &userData{
		userName:        userInfo.UserName,
		password:        userInfo.Password,
		google2faSecret: userInfo.Google2FASecretKey,
	}
	impl.name2UserIDs[userInfo.UserName] = userInfo.ID

	if len(impl.users) == 1 {
		impl.users[userInfo.ID].adminFlag = true
	}

	for _, flag := range userInfo.AdminFlags {
		if flag.UserID == 0 {
			continue
		}

		if _, exists := impl.users[flag.UserID]; exists {
			impl.users[flag.UserID].adminFlag = flag.Flag
		}
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}
