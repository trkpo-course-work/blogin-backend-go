// Code generated by MockGen. DO NOT EDIT.
// Source: internal/jwt/jwt.go

// Package mock_jwt is a generated GoMock package.
package mock_jwt

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// CreateToken mocks base method.
func (m *MockManager) CreateToken(id int64) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateToken", id)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateToken indicates an expected call of CreateToken.
func (mr *MockManagerMockRecorder) CreateToken(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateToken", reflect.TypeOf((*MockManager)(nil).CreateToken), id)
}

// GetIdFromToken mocks base method.
func (m *MockManager) GetIdFromToken(token string) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIdFromToken", token)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIdFromToken indicates an expected call of GetIdFromToken.
func (mr *MockManagerMockRecorder) GetIdFromToken(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIdFromToken", reflect.TypeOf((*MockManager)(nil).GetIdFromToken), token)
}
