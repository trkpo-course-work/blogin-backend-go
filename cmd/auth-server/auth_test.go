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
	mockemail "github.com/SergeyKozhin/blogin-auth/mocks/email"
	mockjwt "github.com/SergeyKozhin/blogin-auth/mocks/jwt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	validCode     = "validCode"
	invalidCode   = "invalidCode"
	generatedCode = "aaaaa"

	validLogin   = "validLogin"
	invalidLogin = "invalidLogin"

	validPass   = "validPass"
	newPass     = "newPass"
	invalidPass = "invalidPass"

	validEmail         = "valid@email.com"
	invalidEmail       = "invalid@email.com"
	validID      int64 = 1

	validAccessToken      = "validAccessToken"
	invalidAccessToken    = "invalidAccessToken"
	validRefreshToken     = "validRefreshToken"
	invalidRefreshToken   = "invalidRefreshToken"
	generatedRefreshToken = "aaaaa"

	refreshTokenLength     = 5
	confirmationCodeLength = 5
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

	notFoundBody           = map[string]string{"error": "the requested resource could not be found"}
	userNotConfirmedBody   = map[string]string{"error": "user not confirmed"}
	invalidCredentialsBody = map[string]string{"error": "invalid credentials"}
	noSuchSessionBody      = map[string]string{"error": "no such session"}
	alreadyConfirmedBody   = map[string]string{"error": "user already confirmed"}
	serverErrorBody        = map[string]string{"error": "the server encountered a problem and could not process your request"}

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
	refreshTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	app := &application{
		config:        &config{SessionTokenLength: refreshTokenLength},
		logger:        zap.NewNop().Sugar(),
		users:         usersMock,
		jwts:          jwtMock,
		refreshTokens: refreshTokensMock,
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
					refreshTokensMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedRefreshToken), gomock.Eq(validID)).Return(nil),
				)
			},
			wantCode: http.StatusOK,
			wantBody: output{
				AccessToken:  validAccessToken,
				RefreshToken: generatedRefreshToken,
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
			wantBody: userNotConfirmedBody,
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
					refreshTokensMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedRefreshToken), gomock.Eq(validID)).Return(someError),
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

func Test_application_logoutUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	refreshTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	app := &application{
		logger:        zap.NewNop().Sugar(),
		refreshTokens: refreshTokensMock,
	}

	type input struct {
		RefreshToken string `json:"refresh_token"`
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
			name:  "valid refresh token",
			input: input{RefreshToken: validRefreshToken},
			prepareMocks: func() {
				refreshTokensMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validRefreshToken)).Return(nil)
			},
			wantCode:  http.StatusOK,
			emptyBody: true,
		},
		{
			name:  "invalid refresh token",
			input: input{RefreshToken: invalidRefreshToken},
			prepareMocks: func() {
				refreshTokensMock.EXPECT().Delete(gomock.Any(), gomock.Eq(invalidRefreshToken)).Return(models.ErrNoRecord)
			},
			wantCode: http.StatusUnauthorized,
			wantBody: noSuchSessionBody,
		},
		{
			name:  "deleting token error",
			input: input{RefreshToken: validRefreshToken},
			prepareMocks: func() {
				refreshTokensMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validRefreshToken)).Return(someError)
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

			app.logoutUserHandler(w, req)

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

func Test_application_refreshTokenHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	jwtMock := mockjwt.NewMockManager(ctrl)
	refreshTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	app := &application{
		config:        &config{SessionTokenLength: refreshTokenLength},
		logger:        zap.NewNop().Sugar(),
		jwts:          jwtMock,
		refreshTokens: refreshTokensMock,
		randSource:    &constReader{},
	}

	type input struct {
		RefreshToken string `json:"refresh_token"`
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
			name:  "valid refresh token",
			input: input{RefreshToken: validRefreshToken},
			prepareMocks: func() {
				gomock.InOrder(
					refreshTokensMock.EXPECT().Get(gomock.Any(), gomock.Eq(validRefreshToken)).Return(validID, nil),
					jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return(validAccessToken, nil),
					refreshTokensMock.EXPECT().Refresh(gomock.Any(), gomock.Eq(validRefreshToken), gomock.Eq(generatedRefreshToken)).Return(nil),
				)
			},
			wantCode: http.StatusOK,
			wantBody: output{
				AccessToken:  validAccessToken,
				RefreshToken: generatedRefreshToken,
			},
		},
		{
			name:  "invalid refresh token",
			input: input{RefreshToken: invalidRefreshToken},
			prepareMocks: func() {
				gomock.InOrder(
					refreshTokensMock.EXPECT().Get(gomock.Any(), gomock.Eq(invalidRefreshToken)).Return(int64(0), models.ErrNoRecord),
				)
			},
			wantCode: http.StatusUnauthorized,
			wantBody: noSuchSessionBody,
		},
		{
			name:  "get id from token error",
			input: input{RefreshToken: validRefreshToken},
			prepareMocks: func() {
				gomock.InOrder(
					refreshTokensMock.EXPECT().Get(gomock.Any(), gomock.Eq(validRefreshToken)).Return(int64(0), someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name:  "create access token error",
			input: input{RefreshToken: validRefreshToken},
			prepareMocks: func() {
				gomock.InOrder(
					refreshTokensMock.EXPECT().Get(gomock.Any(), gomock.Eq(validRefreshToken)).Return(validID, nil),
					jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return("", someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name:  "refresh token error",
			input: input{RefreshToken: validRefreshToken},
			prepareMocks: func() {
				gomock.InOrder(
					refreshTokensMock.EXPECT().Get(gomock.Any(), gomock.Eq(validRefreshToken)).Return(validID, nil),
					jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return(validAccessToken, nil),
					refreshTokensMock.EXPECT().Refresh(gomock.Any(), gomock.Eq(validRefreshToken), gomock.Eq(generatedRefreshToken)).Return(someError),
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

			app.refreshTokenHandler(w, req)

			assert.Equal(t, tt.wantCode, w.Code)

			outputJSON, err := json.Marshal(tt.wantBody)
			assert.NoError(t, err)
			assert.Equal(t, outputJSON, w.Body.Bytes())
		})
	}
}

func Test_application_requestConfirmationHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)
	emailMock := mockemail.NewMockMailSender(ctrl)

	app := &application{
		config:     &config{CodeLength: confirmationCodeLength, TestAccountSuffix: "@test.com"},
		logger:     zap.NewNop().Sugar(),
		users:      usersMock,
		codes:      codeMock,
		mail:       emailMock,
		randSource: &constReader{},
	}

	type input struct {
		Login string `json:"login"`
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
			name:  "valid login, unconfirmed user",
			input: input{Login: validLogin},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
					codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
					emailMock.EXPECT().SendConfirmationCode(gomock.Eq(validEmail), generatedCode).Return(nil),
				)
			},
			wantCode:  http.StatusOK,
			emptyBody: true,
		},
		{
			name:  "valid login, confirmed user",
			input: input{Login: validLogin},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
				)
			},
			wantCode: http.StatusForbidden,
			wantBody: alreadyConfirmedBody,
		},
		{
			name:  "invalid login",
			input: input{Login: invalidLogin},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(invalidLogin)).Return(nil, models.ErrNoRecord),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name:  "get user by login error",
			input: input{Login: validLogin},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(nil, someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name:  "save code error",
			input: input{Login: validLogin},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
					codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name:  "send email error",
			input: input{Login: validLogin},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
					codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
					emailMock.EXPECT().SendConfirmationCode(gomock.Eq(validEmail), generatedCode).Return(someError),
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

			app.requestConfirmationHandler(w, req)

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

func Test_application_requestResetHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)
	emailMock := mockemail.NewMockMailSender(ctrl)

	app := &application{
		config:     &config{CodeLength: confirmationCodeLength},
		logger:     zap.NewNop().Sugar(),
		users:      usersMock,
		codes:      codeMock,
		mail:       emailMock,
		randSource: &constReader{},
	}

	type input struct {
		Email string `json:"email"`
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
			name:  "valid email, confirmed user",
			input: input{Email: validEmail},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(validEmail)).Return(confirmedUser, nil),
					codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
					emailMock.EXPECT().SendResetCode(gomock.Eq(validEmail), gomock.Eq(generatedCode)),
				)
			},
			wantCode:  http.StatusOK,
			emptyBody: true,
		},
		{
			name:  "valid email, unconfirmed user",
			input: input{Email: validEmail},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(validEmail)).Return(unconfirmedUser, nil),
				)
			},
			wantCode: http.StatusForbidden,
			wantBody: userNotConfirmedBody,
		},
		{
			name:  "invalid email",
			input: input{Email: invalidEmail},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(invalidEmail)).Return(nil, models.ErrNoRecord),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name:  "get user by email error",
			input: input{Email: validEmail},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(validEmail)).Return(nil, someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name:  "save code error",
			input: input{Email: validEmail},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(validEmail)).Return(confirmedUser, nil),
					codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name:  "send email error",
			input: input{Email: validEmail},
			prepareMocks: func() {
				gomock.InOrder(
					usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(validEmail)).Return(confirmedUser, nil),
					codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
					emailMock.EXPECT().SendResetCode(gomock.Eq(validEmail), generatedCode).Return(someError),
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

			app.requestResetHandler(w, req)

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

func Test_application_resetHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)

	app := &application{
		logger: zap.NewNop().Sugar(),
		users:  usersMock,
		codes:  codeMock,
	}

	type input struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
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
			name: "valid email, code and password",
			input: input{
				Email:    validEmail,
				Code:     validCode,
				Password: newPass,
			},
			prepareMocks: func() {
				userCopy := *confirmedUser
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
					usersMock.EXPECT().Update(gomock.Any(), IsUserWithPassword(confirmedUser, newPass)).Return(nil),
					codeMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(nil),
				)
			},
			wantCode:  http.StatusOK,
			emptyBody: true,
		},
		{
			name: "valid email and code, empty password",
			input: input{
				Email:    validEmail,
				Code:     validCode,
				Password: "",
			},
			prepareMocks: func() {},
			wantCode:     http.StatusUnprocessableEntity,
			wantBody: map[string]interface{}{
				"error": map[string]string{
					"password": "password must be provided",
				},
			},
		},
		{
			name: "invalid code",
			input: input{
				Email:    validEmail,
				Code:     invalidCode,
				Password: newPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(invalidCode)).Return(int64(0), models.ErrNoRecord),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name: "valid code, invalid email",
			input: input{
				Email:    invalidEmail,
				Code:     validCode,
				Password: newPass,
			},
			prepareMocks: func() {
				userCopy := *confirmedUser
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
				)
			},
			wantCode: http.StatusNotFound,
			wantBody: notFoundBody,
		},
		{
			name: "get id from code error",
			input: input{
				Email:    validEmail,
				Code:     validCode,
				Password: newPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(int64(0), someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "get user by id error",
			input: input{
				Email:    validEmail,
				Code:     validCode,
				Password: newPass,
			},
			prepareMocks: func() {
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(nil, someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "update user error",
			input: input{
				Email:    validEmail,
				Code:     validCode,
				Password: newPass,
			},
			prepareMocks: func() {
				userCopy := *confirmedUser
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
					usersMock.EXPECT().Update(gomock.Any(), IsUserWithPassword(confirmedUser, newPass)).Return(someError),
				)
			},
			wantCode: http.StatusInternalServerError,
			wantBody: serverErrorBody,
		},
		{
			name: "delete code error",
			input: input{
				Email:    validEmail,
				Code:     validCode,
				Password: newPass,
			},
			prepareMocks: func() {
				userCopy := *confirmedUser
				gomock.InOrder(
					codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
					usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
					usersMock.EXPECT().Update(gomock.Any(), IsUserWithPassword(confirmedUser, newPass)).Return(nil),
					codeMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(someError),
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

			app.resetHandler(w, req)

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

func Test_application_signupUserHandler(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)

	app := &application{
		logger: zap.NewNop().Sugar(),
		users:  usersMock,
	}

	type input struct {
		FullName string `json:"full_name"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
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
			name: "valid input",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    validLogin,
				Email:    validEmail,
				Password: validPass,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				userCopy.ID = 0
				usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy, validPass)).Return(nil)
			},
			wantCode:  http.StatusCreated,
			emptyBody: true,
		},
		{
			name: "invalid full name",
			input: input{
				FullName: "",
				Login:    validLogin,
				Email:    validEmail,
				Password: validPass,
			},
			prepareMocks: func() {},
			wantCode:     http.StatusUnprocessableEntity,
			wantBody: map[string]interface{}{
				"error": map[string]string{
					"full_name": "full name name must be provided",
				},
			},
		},
		{
			name: "invalid login and password",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    "",
				Email:    validEmail,
				Password: "",
			},
			prepareMocks: func() {},
			wantCode:     http.StatusUnprocessableEntity,
			wantBody: map[string]interface{}{
				"error": map[string]string{
					"login":    "login name must be provided",
					"password": "password must be provided",
				},
			},
		},
		{
			name: "invalid email and password",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    validLogin,
				Email:    "notEmail",
				Password: "",
			},
			prepareMocks: func() {},
			wantCode:     http.StatusUnprocessableEntity,
			wantBody: map[string]interface{}{
				"error": map[string]string{
					"email":    "valid email must be provided",
					"password": "password must be provided",
				},
			},
		},
		{
			name: "invalid login and email",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    "",
				Email:    "notEmail",
				Password: validPass,
			},
			prepareMocks: func() {},
			wantCode:     http.StatusUnprocessableEntity,
			wantBody: map[string]interface{}{
				"error": map[string]string{
					"login": "login name must be provided",
					"email": "valid email must be provided",
				},
			},
		},
		{
			name: "all invalid",
			input: input{
				FullName: "",
				Login:    "",
				Email:    "notEmail",
				Password: "",
			},
			prepareMocks: func() {},
			wantCode:     http.StatusUnprocessableEntity,
			wantBody: map[string]interface{}{
				"error": map[string]string{
					"full_name": "full name name must be provided",
					"login":     "login name must be provided",
					"email":     "valid email must be provided",
					"password":  "password must be provided",
				},
			},
		},
		{
			name: "email already in use",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    validLogin,
				Email:    validEmail,
				Password: validPass,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				userCopy.ID = 0
				usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy, validPass)).Return(&models.ErrUserAlreadyExists{Column: "email"})
			},
			wantCode: http.StatusConflict,
			wantBody: map[string]string{"error": "email is already in use"},
		},
		{
			name: "email already in use",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    validLogin,
				Email:    validEmail,
				Password: validPass,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				userCopy.ID = 0
				usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy, validPass)).Return(&models.ErrUserAlreadyExists{Column: "login"})
			},
			wantCode: http.StatusConflict,
			wantBody: map[string]string{"error": "login is already in use"},
		},
		{
			name: "saving user error",
			input: input{
				FullName: confirmedUser.FullName,
				Login:    validLogin,
				Email:    validEmail,
				Password: validPass,
			},
			prepareMocks: func() {
				userCopy := *unconfirmedUser
				userCopy.ID = 0
				usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy, validPass)).Return(someError)
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

			app.signupUserHandler(w, req)

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
