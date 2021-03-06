// Code generated by MockGen. DO NOT EDIT.
// Source: internal/data/repositories.go

// Package mock_data is a generated GoMock package.
package mock_data

import (
	context "context"
	reflect "reflect"

	models "github.com/SergeyKozhin/blogin-auth/internal/data/models"
	gomock "github.com/golang/mock/gomock"
)

// MockUserRepository is a mock of UserRepository interface.
type MockUserRepository struct {
	ctrl     *gomock.Controller
	recorder *MockUserRepositoryMockRecorder
}

// MockUserRepositoryMockRecorder is the mock recorder for MockUserRepository.
type MockUserRepositoryMockRecorder struct {
	mock *MockUserRepository
}

// NewMockUserRepository creates a new mock instance.
func NewMockUserRepository(ctrl *gomock.Controller) *MockUserRepository {
	mock := &MockUserRepository{ctrl: ctrl}
	mock.recorder = &MockUserRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserRepository) EXPECT() *MockUserRepositoryMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockUserRepository) Add(ctx context.Context, user *models.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockUserRepositoryMockRecorder) Add(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockUserRepository)(nil).Add), ctx, user)
}

// Delete mocks base method.
func (m *MockUserRepository) Delete(ctx context.Context, id int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockUserRepositoryMockRecorder) Delete(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockUserRepository)(nil).Delete), ctx, id)
}

// GetByEmail mocks base method.
func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByEmail", ctx, email)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByEmail indicates an expected call of GetByEmail.
func (mr *MockUserRepositoryMockRecorder) GetByEmail(ctx, email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByEmail", reflect.TypeOf((*MockUserRepository)(nil).GetByEmail), ctx, email)
}

// GetByID mocks base method.
func (m *MockUserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByID", ctx, id)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByID indicates an expected call of GetByID.
func (mr *MockUserRepositoryMockRecorder) GetByID(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByID", reflect.TypeOf((*MockUserRepository)(nil).GetByID), ctx, id)
}

// GetByLogin mocks base method.
func (m *MockUserRepository) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByLogin", ctx, login)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByLogin indicates an expected call of GetByLogin.
func (mr *MockUserRepositoryMockRecorder) GetByLogin(ctx, login interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByLogin", reflect.TypeOf((*MockUserRepository)(nil).GetByLogin), ctx, login)
}

// Update mocks base method.
func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockUserRepositoryMockRecorder) Update(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockUserRepository)(nil).Update), ctx, user)
}

// MockPicturesRepository is a mock of PicturesRepository interface.
type MockPicturesRepository struct {
	ctrl     *gomock.Controller
	recorder *MockPicturesRepositoryMockRecorder
}

// MockPicturesRepositoryMockRecorder is the mock recorder for MockPicturesRepository.
type MockPicturesRepositoryMockRecorder struct {
	mock *MockPicturesRepository
}

// NewMockPicturesRepository creates a new mock instance.
func NewMockPicturesRepository(ctrl *gomock.Controller) *MockPicturesRepository {
	mock := &MockPicturesRepository{ctrl: ctrl}
	mock.recorder = &MockPicturesRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPicturesRepository) EXPECT() *MockPicturesRepositoryMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockPicturesRepository) Add(ctx context.Context, p *models.Picture) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", ctx, p)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockPicturesRepositoryMockRecorder) Add(ctx, p interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockPicturesRepository)(nil).Add), ctx, p)
}

// Delete mocks base method.
func (m *MockPicturesRepository) Delete(ctx context.Context, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockPicturesRepositoryMockRecorder) Delete(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockPicturesRepository)(nil).Delete), ctx, id)
}

// GetByID mocks base method.
func (m *MockPicturesRepository) GetByID(ctx context.Context, id int64) (*models.Picture, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByID", ctx, id)
	ret0, _ := ret[0].(*models.Picture)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByID indicates an expected call of GetByID.
func (mr *MockPicturesRepositoryMockRecorder) GetByID(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByID", reflect.TypeOf((*MockPicturesRepository)(nil).GetByID), ctx, id)
}

// MockCodesRepository is a mock of CodesRepository interface.
type MockCodesRepository struct {
	ctrl     *gomock.Controller
	recorder *MockCodesRepositoryMockRecorder
}

// MockCodesRepositoryMockRecorder is the mock recorder for MockCodesRepository.
type MockCodesRepositoryMockRecorder struct {
	mock *MockCodesRepository
}

// NewMockCodesRepository creates a new mock instance.
func NewMockCodesRepository(ctrl *gomock.Controller) *MockCodesRepository {
	mock := &MockCodesRepository{ctrl: ctrl}
	mock.recorder = &MockCodesRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCodesRepository) EXPECT() *MockCodesRepositoryMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockCodesRepository) Add(ctx context.Context, code string, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", ctx, code, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockCodesRepositoryMockRecorder) Add(ctx, code, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockCodesRepository)(nil).Add), ctx, code, id)
}

// Delete mocks base method.
func (m *MockCodesRepository) Delete(ctx context.Context, code string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, code)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockCodesRepositoryMockRecorder) Delete(ctx, code interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockCodesRepository)(nil).Delete), ctx, code)
}

// Get mocks base method.
func (m *MockCodesRepository) Get(ctx context.Context, code string) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, code)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockCodesRepositoryMockRecorder) Get(ctx, code interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockCodesRepository)(nil).Get), ctx, code)
}

// MockRefreshTokenRepository is a mock of RefreshTokenRepository interface.
type MockRefreshTokenRepository struct {
	ctrl     *gomock.Controller
	recorder *MockRefreshTokenRepositoryMockRecorder
}

// MockRefreshTokenRepositoryMockRecorder is the mock recorder for MockRefreshTokenRepository.
type MockRefreshTokenRepositoryMockRecorder struct {
	mock *MockRefreshTokenRepository
}

// NewMockRefreshTokenRepository creates a new mock instance.
func NewMockRefreshTokenRepository(ctrl *gomock.Controller) *MockRefreshTokenRepository {
	mock := &MockRefreshTokenRepository{ctrl: ctrl}
	mock.recorder = &MockRefreshTokenRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRefreshTokenRepository) EXPECT() *MockRefreshTokenRepositoryMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockRefreshTokenRepository) Add(ctx context.Context, session string, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", ctx, session, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockRefreshTokenRepositoryMockRecorder) Add(ctx, session, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockRefreshTokenRepository)(nil).Add), ctx, session, id)
}

// Delete mocks base method.
func (m *MockRefreshTokenRepository) Delete(ctx context.Context, session string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, session)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockRefreshTokenRepositoryMockRecorder) Delete(ctx, session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockRefreshTokenRepository)(nil).Delete), ctx, session)
}

// DeleteByUserID mocks base method.
func (m *MockRefreshTokenRepository) DeleteByUserID(ctx context.Context, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByUserID", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByUserID indicates an expected call of DeleteByUserID.
func (mr *MockRefreshTokenRepositoryMockRecorder) DeleteByUserID(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByUserID", reflect.TypeOf((*MockRefreshTokenRepository)(nil).DeleteByUserID), ctx, id)
}

// DeleteExpired mocks base method.
func (m *MockRefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteExpired", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteExpired indicates an expected call of DeleteExpired.
func (mr *MockRefreshTokenRepositoryMockRecorder) DeleteExpired(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteExpired", reflect.TypeOf((*MockRefreshTokenRepository)(nil).DeleteExpired), ctx)
}

// Get mocks base method.
func (m *MockRefreshTokenRepository) Get(ctx context.Context, session string) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, session)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRefreshTokenRepositoryMockRecorder) Get(ctx, session interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRefreshTokenRepository)(nil).Get), ctx, session)
}

// Refresh mocks base method.
func (m *MockRefreshTokenRepository) Refresh(ctx context.Context, old, new string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Refresh", ctx, old, new)
	ret0, _ := ret[0].(error)
	return ret0
}

// Refresh indicates an expected call of Refresh.
func (mr *MockRefreshTokenRepositoryMockRecorder) Refresh(ctx, old, new interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Refresh", reflect.TypeOf((*MockRefreshTokenRepository)(nil).Refresh), ctx, old, new)
}
