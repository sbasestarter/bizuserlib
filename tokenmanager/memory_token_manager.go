package tokenmanager

import (
	"context"
	"sync"

	uuid "github.com/satori/go.uuid"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func NewMemoryTokenManager() bizuserinters.TokenManager {
	return &tokenManagerImpl{
		m: make(map[string]*TokenData),
	}
}

type TokenData struct {
	CompletedAuthenticatorEvent map[bizuserinters.AuthenticatorEvent]interface{}
	AuthenticatorData           map[bizuserinters.AuthenticatorEvent]map[string]interface{}
	UserID                      uint64
	UserName                    string
	WorkData                    map[string][]byte
}

type tokenManagerImpl struct {
	lock sync.Mutex
	m    map[string]*TokenData
}

func (impl *tokenManagerImpl) CreateToken(ctx context.Context) (bizID string, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	bizID = uuid.NewV4().String()
	impl.m[bizID] = &TokenData{
		CompletedAuthenticatorEvent: make(map[bizuserinters.AuthenticatorEvent]interface{}),
		AuthenticatorData:           make(map[bizuserinters.AuthenticatorEvent]map[string]interface{}),
		WorkData:                    make(map[string][]byte),
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) DeleteToken(bizID string) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	delete(impl.m, bizID)
}

func (impl *tokenManagerImpl) MarkAuthenticatorEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	td.CompletedAuthenticatorEvent[e] = true

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) HasAuthenticatorEventCompleted(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent) (status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	if _, ok = td.CompletedAuthenticatorEvent[e]; ok {
		status.Code = bizuserinters.StatusCodeOk
	} else {
		status.Code = bizuserinters.StatusCodeNotCompleted
	}

	return
}

func (impl *tokenManagerImpl) GetAllCompletedAuthenticatorEvents(ctx context.Context, bizID string) (es []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	for event := range td.CompletedAuthenticatorEvent {
		es = append(es, event)
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) SetAuthenticatorData(ctx context.Context, bizID string, e bizuserinters.AuthenticatorEvent, ds map[string]interface{}) (status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	td.AuthenticatorData[e] = ds

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) GetAllAuthenticatorDatas(ctx context.Context, bizID string, e bizuserinters.Event) (ds map[bizuserinters.AuthenticatorIdentity]map[string]interface{}, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	ds = make(map[bizuserinters.AuthenticatorIdentity]map[string]interface{})

	for event, m := range td.AuthenticatorData {
		if event.Event != e {
			continue
		}

		ds[event.Authenticator] = m
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) SetWorkData(ctx context.Context, bizID string, key string, d []byte) (
	status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	td.WorkData[key] = d

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) GetWorkData(ctx context.Context, bizID string, key string) (
	d []byte, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	d, ok = td.WorkData[key]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) SetCurrentUserInfo(ctx context.Context, bizID string, ui *bizuserinters.UserIdentity) (status bizuserinters.Status) {
	if ui == nil {
		status.Code = bizuserinters.StatusCodeInvalidArgsError

		return
	}

	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	td.UserID = ui.ID
	td.UserName = ui.UserName
	status.Code = bizuserinters.StatusCodeOk

	return
}

func (impl *tokenManagerImpl) GetCurrentUserInfo(_ context.Context, bizID string) (
	ui *bizuserinters.UserIdentity, status bizuserinters.Status) {
	impl.lock.Lock()
	defer impl.lock.Unlock()

	td, ok := impl.m[bizID]
	if !ok {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	if td.UserID == 0 && td.UserName == "" {
		status.Code = bizuserinters.StatusCodeNoDataError

		return
	}

	ui = &bizuserinters.UserIdentity{
		ID:       td.UserID,
		UserName: td.UserName,
	}
	status.Code = bizuserinters.StatusCodeOk

	return
}
