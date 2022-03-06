package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	mockdata "github.com/SergeyKozhin/blogin-auth/mocks/data"
	mockjwt "github.com/SergeyKozhin/blogin-auth/mocks/jwt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	validCode   = "validCode"
	invalidCode = "invalidCode"

	validLogin   = "validLogin"
	invalidLogin = "invalidLogin"

	validPass   = "validPass"
	invalidPass = "invalidPass"

	validEmail         = "valid@email.com"
	invalidEmail       = "invalid@email.com"
	validID      int64 = 1

	validAccessToken    = "validAccessToken"
	invalidAccessToken  = "invalidAccessToken"
	validRefreshToken   = "aaaaa"
	invalidRefreshToken = "invalidRefreshToken"
)

var (
	unconfirmedUser = &models.User{
		ID:           validID,
		FullName:     "Name",
		Login:        validLogin,
		Email:        validEmail,
		PasswordHash: "$2a$12$a07XUyfhPkVINU.bugPe5ez1Muw0NPIQb2Qh1hsspVbc1pI0HttBi",
		Confirmed:    false,
	}

	confirmedUser = &models.User{
		ID:           validID,
		FullName:     "Name",
		Login:        validLogin,
		Email:        validEmail,
		PasswordHash: "$2a$12$a07XUyfhPkVINU.bugPe5ez1Muw0NPIQb2Qh1hsspVbc1pI0HttBi",
		Confirmed:    true,
	}

	notFoundBody            = map[string]string{"error": "the requested resource could not be found"}
	accountNotConfirmedBody = map[string]string{"error": "account not confirmed"}
	invalidCredentialsBody  = map[string]string{"error": "invalid credentials"}
	serverErrorBody         = map[string]string{"error": "the server encountered a problem and could not process your request"}

	someError = errors.New("some error")
)

type constReader struct{}

func (cr *constReader) Read(buf []byte) (n int, err error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func Test_application_checkResetHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codesMock := mockdata.NewMockCodesRepository(ctrl)

	app := &application{
		logger: zap.NewNop().Sugar(),
		users:  usersMock,
		codes:  codesMock,
	}

	type input struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	tests := []struct {
		name         string
		input        input
		prepareMocks func()
		wantCode     int
		emptyBody    bool
		wantBody     interface{}
	}{
		{
			name: "valid code and email",
			input: input{
				Email: validEmail,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&models.User{Email: validEmail}, nil),
				)
			},
			wantCode:  http.StatusOK,
			emptyBody: true,
		},
		{
			name: "invalid code",
			input: input{
				Email: validEmail,
				Code:  invalidCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(invalidCode)).Return(int64(0), models.ErrNoRecord),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name: "valid code, invalid email",
			input: input{
				Email: invalidEmail,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&models.User{Email: validEmail}, nil),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name: "code error",
			input: input{
				Email: validEmail,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(int64(0), someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "user error",
			input: input{
				Email: validEmail,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(nil, someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepareMocks()

			inputJSON, err := json.Marshal(tt.input)
			assert.NoError(t, err)

			req := httptest.NewRequest("", "/", bytes.NewBuffer(inputJSON))
			w := httptest.NewRecorder()

			app.checkResetHandler(w, req)

			assert.Equal(t, tt.wantCode, w.Code)

			if tt.emptyBody {
				assert.Empty(t, w.Body.Bytes())
			} else {
				outputJSON, err := json.Marshal(tt.wantBody)
				assert.NoError(t, err)
				assert.Equal(t, outputJSON, w.Body.Bytes())
			}
		})
	}
}

func Test_application_confirmHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codesMock := mockdata.NewMockCodesRepository(ctrl)

	app := &application{
		logger: zap.NewNop().Sugar(),
		users:  usersMock,
		codes:  codesMock,
	}

	type input struct {
		Login string `json:"login"`
		Code  string `json:"code"`
	}

	tests := []struct {
		name         string
		input        input
		prepareMocks func()
		wantCode     int
		emptyBody    bool
		wantBody     interface{}
	}{
		{
			name: "valid code and login, unconfirmed user",
			input: input{
				Login: validLogin,
				Code:  validCode,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
					usersMock.EXPECT().Update(gomock.Any(), gomock.Eq(confirmedUser)).Return(nil),
					codesMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(nil),
				)
			},
			wantCode:  http.StatusOK,
			emptyBody: true,
		},
		{
			name: "invalid code",
			input: input{
				Login: validLogin,
				Code:  invalidCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(invalidCode)).Return(int64(0), models.ErrNoRecord),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name: "valid code and invalid login",
			input: input{
				Login: invalidLogin,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(unconfirmedUser, nil),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name: "get id by code error",
			input: input{
				Login: validLogin,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(int64(0), someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "get user error",
			input: input{
				Login: validLogin,
				Code:  validCode,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(nil, someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "update user error",
			input: input{
				Login: validLogin,
				Code:  validCode,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
					usersMock.EXPECT().Update(gomock.Any(), gomock.Eq(confirmedUser)).Return(someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "delete code error",
			input: input{
				Login: validLogin,
				Code:  validCode,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				gomock.InOrder(
					codesMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
					usersMock.EXPECT().Update(gomock.Any(), gomock.Eq(confirmedUser)).Return(nil),
					codesMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepareMocks()

			inputJSON, err := json.Marshal(tt.input)
			assert.NoError(t, err)

			req := httptest.NewRequest("", "/", bytes.NewBuffer(inputJSON))
			w := httptest.NewRecorder()

			app.confirmHandler(w, req)

			assert.Equal(t, tt.wantCode, w.Code)

			if tt.emptyBody {
				assert.Empty(t, w.Body.Bytes())
			} else {
				outputJSON, err := json.Marshal(tt.wantBody)
				assert.NoError(t, err)
				assert.Equal(t, outputJSON, w.Body.Bytes())
			}
		})
	}
}

func Test_application_loginUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	jwtMock := mockjwt.NewMockManager(ctrl)
	refershTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	app := &application{
		config:        &config{SessionTokenLength: 5},
		logger:        zap.NewNop().Sugar(),
		users:         usersMock,
		jwts:          jwtMock,
		refreshTokens: refershTokensMock,
		randSource:    &constReader{},
	}

	type input struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	type output struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	tests := []struct {
		name         string
		input        input
		prepareMocks func()
		wantCode     int
		wantBody     interface{}
	}{
		{
			name: "valid login and password, confirmed user",
			input: input{
				Login:    validLogin,
				Password: validPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
					jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return(validAccessToken, nil),
					refershTokensMock.EXPECT().Add(gomock.Any(), gomock.Eq(validRefreshToken), gomock.Eq(validID)).Return(nil),
				)
			},
			wantCode: http.StatusOK,
			wantBody: output{
				AccessToken:  validAccessToken,
				RefreshToken: validRefreshToken,
			},
		},
		{
			name: "valid login and password, unconfirmed user",
			input: input{
				Login:    validLogin,
				Password: validPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
				)
			},
			wantCode: http.StatusForbidden,
			wantBody: accountNotConfirmedBody,
		},
		{
			name: "valid login and invalid password",
			input: input{
				Login:    validLogin,
				Password: invalidPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
				)
			},
			wantCode: http.StatusUnauthorized,
			wantBody: invalidCredentialsBody,
		},
		{
			name: "invalid login",
			input: input{
				Login:    invalidLogin,
				Password: validPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(invalidLogin)).Return(nil, models.ErrNoRecord),
				)
			},
			wantCode: http.StatusUnauthorized,
			wantBody: invalidCredentialsBody,
		},
		{
			name: "get user error",
			input: input{
				Login:    validLogin,
				Password: validPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(nil, someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "create token error",
			input: input{
				Login:    validLogin,
				Password: validPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
					jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return("", someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "save refresh token error",
			input: input{
				Login:    validLogin,
				Password: validPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
					jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return(validAccessToken, nil),
					refershTokensMock.EXPECT().Add(gomock.Any(), gomock.Eq(validRefreshToken), gomock.Eq(validID)).Return(someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepareMocks()

			inputJSON, err := json.Marshal(tt.input)
			assert.NoError(t, err)

			req := httptest.NewRequest("", "/", bytes.NewBuffer(inputJSON))
			w := httptest.NewRecorder()

			app.loginUserHandler(w, req)

			assert.Equal(t, tt.wantCode, w.Code)

			outputJSON, err := json.Marshal(tt.wantBody)
			assert.NoError(t, err)
			assert.Equal(t, outputJSON, w.Body.Bytes())
		})
	}
}

//func Test_application_logoutUserHandler(t *testing.T) {
//	type fields struct {
//		config        *config
//		logger        *zap.SugaredLogger
//		jwts          *jwt.Manager
//		refreshTokens data.RefreshTokenRepository
//		users         data.UserRepository
//		codes         data.CodesRepository
//		mail          email.MailSender
//	}
//	type args struct {
//		w http.ResponseWriter
//		r *http.Request
//	}
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			app := &application{
//				config:        tt.fields.config,
//				logger:        tt.fields.logger,
//				jwts:          tt.fields.jwts,
//				refreshTokens: tt.fields.refreshTokens,
//				users:         tt.fields.users,
//				codes:         tt.fields.codes,
//				mail:          tt.fields.mail,
//			}
//		})
//	}
//}
//
//func Test_application_refreshTokenHandler(t *testing.T) {
//	type fields struct {
//		config        *config
//		logger        *zap.SugaredLogger
//		jwts          *jwt.Manager
//		refreshTokens data.RefreshTokenRepository
//		users         data.UserRepository
//		codes         data.CodesRepository
//		mail          email.MailSender
//	}
//	type args struct {
//		w http.ResponseWriter
//		r *http.Request
//	}
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			app := &application{
//				config:        tt.fields.config,
//				logger:        tt.fields.logger,
//				jwts:          tt.fields.jwts,
//				refreshTokens: tt.fields.refreshTokens,
//				users:         tt.fields.users,
//				codes:         tt.fields.codes,
//				mail:          tt.fields.mail,
//			}
//		})
//	}
//}
//
//func Test_application_requestConfirmationHandler(t *testing.T) {
//	type fields struct {
//		config        *config
//		logger        *zap.SugaredLogger
//		jwts          *jwt.Manager
//		refreshTokens data.RefreshTokenRepository
//		users         data.UserRepository
//		codes         data.CodesRepository
//		mail          email.MailSender
//	}
//	type args struct {
//		w http.ResponseWriter
//		r *http.Request
//	}
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			app := &application{
//				config:        tt.fields.config,
//				logger:        tt.fields.logger,
//				jwts:          tt.fields.jwts,
//				refreshTokens: tt.fields.refreshTokens,
//				users:         tt.fields.users,
//				codes:         tt.fields.codes,
//				mail:          tt.fields.mail,
//			}
//		})
//	}
//}
//
//func Test_application_requestResetHandler(t *testing.T) {
//	type fields struct {
//		config        *config
//		logger        *zap.SugaredLogger
//		jwts          *jwt.Manager
//		refreshTokens data.RefreshTokenRepository
//		users         data.UserRepository
//		codes         data.CodesRepository
//		mail          email.MailSender
//	}
//	type args struct {
//		w http.ResponseWriter
//		r *http.Request
//	}
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			app := &application{
//				config:        tt.fields.config,
//				logger:        tt.fields.logger,
//				jwts:          tt.fields.jwts,
//				refreshTokens: tt.fields.refreshTokens,
//				users:         tt.fields.users,
//				codes:         tt.fields.codes,
//				mail:          tt.fields.mail,
//			}
//		})
//	}
//}
//
//func Test_application_resetHandler(t *testing.T) {
//	type fields struct {
//		config        *config
//		logger        *zap.SugaredLogger
//		jwts          *jwt.Manager
//		refreshTokens data.RefreshTokenRepository
//		users         data.UserRepository
//		codes         data.CodesRepository
//		mail          email.MailSender
//	}
//	type args struct {
//		w http.ResponseWriter
//		r *http.Request
//	}
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			app := &application{
//				config:        tt.fields.config,
//				logger:        tt.fields.logger,
//				jwts:          tt.fields.jwts,
//				refreshTokens: tt.fields.refreshTokens,
//				users:         tt.fields.users,
//				codes:         tt.fields.codes,
//				mail:          tt.fields.mail,
//			}
//		})
//	}
//}
//
//func Test_application_signupUserHandler(t *testing.T) {
//	type fields struct {
//		config        *config
//		logger        *zap.SugaredLogger
//		jwts          *jwt.Manager
//		refreshTokens data.RefreshTokenRepository
//		users         data.UserRepository
//		codes         data.CodesRepository
//		mail          email.MailSender
//	}
//	type args struct {
//		w http.ResponseWriter
//		r *http.Request
//	}
//	tests := []struct {
//		name   string
//		fields fields
//		args   args
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			app := &application{
//				config:        tt.fields.config,
//				logger:        tt.fields.logger,
//				jwts:          tt.fields.jwts,
//				refreshTokens: tt.fields.refreshTokens,
//				users:         tt.fields.users,
//				codes:         tt.fields.codes,
//				mail:          tt.fields.mail,
//			}
//		})
//	}
//}
