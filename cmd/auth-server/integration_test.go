package main

import (
	"bytes"
	"encoding/json"
	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	mockdata "github.com/SergeyKozhin/blogin-auth/mocks/data"
	mockemail "github.com/SergeyKozhin/blogin-auth/mocks/email"
	mockjwt "github.com/SergeyKozhin/blogin-auth/mocks/jwt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignUpAndLogin(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)
	emailMock := mockemail.NewMockMailSender(ctrl)
	jwtMock := mockjwt.NewMockManager(ctrl)
	refreshTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	userCopy1 := *unconfirmedUser
	userCopy1.ID = 0
	userCopy2 := *unconfirmedUser
	gomock.InOrder(
		usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy1, validPass)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
		codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
		emailMock.EXPECT().SendConfirmationCode(gomock.Eq(validEmail), generatedCode).Return(nil),
		codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
		usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy2, nil),
		usersMock.EXPECT().Update(gomock.Any(), gomock.Eq(confirmedUser)).Return(nil),
		codeMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
		jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return(validAccessToken, nil),
		refreshTokensMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedRefreshToken), gomock.Eq(validID)).Return(nil),
	)

	app := &application{
		config: &config{
			CodeLength:         confirmationCodeLength,
			SessionTokenLength: refreshTokenLength,
			TestAccountSuffix:  "@test.com",
		},
		logger:        zap.NewNop().Sugar(),
		users:         usersMock,
		codes:         codeMock,
		mail:          emailMock,
		jwts:          jwtMock,
		refreshTokens: refreshTokensMock,
		randSource:    &constReader{},
	}

	handler := app.route()

	signUp(t, handler)
	requestConfirm(t, handler)
	confirm(t, handler)
	login(t, handler)
}

func TestResetAndLogin(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)
	emailMock := mockemail.NewMockMailSender(ctrl)
	jwtMock := mockjwt.NewMockManager(ctrl)
	refreshTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	userCopy := *confirmedUser
	gomock.InOrder(
		usersMock.EXPECT().GetByEmail(gomock.Any(), gomock.Eq(validEmail)).Return(confirmedUser, nil),
		codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
		emailMock.EXPECT().SendResetCode(gomock.Eq(validEmail), gomock.Eq(generatedCode)),
		codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
		usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&models.User{Email: validEmail}, nil),
		codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
		usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy, nil),
		usersMock.EXPECT().Update(gomock.Any(), IsUserWithPassword(confirmedUser, newPass)).Return(nil),
		codeMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
		jwtMock.EXPECT().CreateToken(gomock.Eq(validID)).Return(validAccessToken, nil),
		refreshTokensMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedRefreshToken), gomock.Eq(validID)).Return(nil),
	)

	app := &application{
		config: &config{
			CodeLength:         confirmationCodeLength,
			SessionTokenLength: refreshTokenLength,
			TestAccountSuffix:  "@test.com",
		},
		logger:        zap.NewNop().Sugar(),
		users:         usersMock,
		codes:         codeMock,
		mail:          emailMock,
		jwts:          jwtMock,
		refreshTokens: refreshTokensMock,
		randSource:    &constReader{},
	}

	handler := app.route()

	requestReset(t, handler)
	checkReset(t, handler)
	reset(t, handler)
	login(t, handler)
}

func TestSignUpAndIncorrectLogin(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)
	emailMock := mockemail.NewMockMailSender(ctrl)

	userCopy1 := *unconfirmedUser
	userCopy1.ID = 0
	userCopy2 := *unconfirmedUser
	gomock.InOrder(
		usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy1, validPass)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
		codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
		emailMock.EXPECT().SendConfirmationCode(gomock.Eq(validEmail), generatedCode).Return(nil),
		codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(validCode)).Return(validID, nil),
		usersMock.EXPECT().GetByID(gomock.Any(), gomock.Eq(validID)).Return(&userCopy2, nil),
		usersMock.EXPECT().Update(gomock.Any(), gomock.Eq(confirmedUser)).Return(nil),
		codeMock.EXPECT().Delete(gomock.Any(), gomock.Eq(validCode)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(confirmedUser, nil),
	)

	app := &application{
		config: &config{
			CodeLength:         confirmationCodeLength,
			SessionTokenLength: refreshTokenLength,
			TestAccountSuffix:  "@test.com",
		},
		logger:     zap.NewNop().Sugar(),
		users:      usersMock,
		codes:      codeMock,
		mail:       emailMock,
		randSource: &constReader{},
	}

	handler := app.route()

	signUp(t, handler)
	requestConfirm(t, handler)
	confirm(t, handler)
	loginInvalidPass(t, handler)
}

func TestSignUpAndUnconfirmedLogin(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)

	userCopy := *unconfirmedUser
	userCopy.ID = 0
	gomock.InOrder(
		usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy, validPass)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
	)

	app := &application{
		config: &config{
			CodeLength:         confirmationCodeLength,
			SessionTokenLength: refreshTokenLength,
		},
		logger:     zap.NewNop().Sugar(),
		users:      usersMock,
		randSource: &constReader{},
	}

	handler := app.route()

	signUp(t, handler)
	loginUnconfirmed(t, handler)
}

func signUp(t *testing.T, h http.Handler) {
	input := struct {
		FullName string `json:"full_name"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		FullName: confirmedUser.FullName,
		Login:    validLogin,
		Email:    validEmail,
		Password: validPass,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/signup", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func TestSignUpAndInvalidConfirmCode(t *testing.T) {
	ctrl := gomock.NewController(t)

	usersMock := mockdata.NewMockUserRepository(ctrl)
	codeMock := mockdata.NewMockCodesRepository(ctrl)
	emailMock := mockemail.NewMockMailSender(ctrl)
	jwtMock := mockjwt.NewMockManager(ctrl)
	refreshTokensMock := mockdata.NewMockRefreshTokenRepository(ctrl)

	userCopy := *unconfirmedUser
	userCopy.ID = 0
	gomock.InOrder(
		usersMock.EXPECT().Add(gomock.Any(), IsUserWithPassword(&userCopy, validPass)).Return(nil),
		usersMock.EXPECT().GetByLogin(gomock.Any(), gomock.Eq(validLogin)).Return(unconfirmedUser, nil),
		codeMock.EXPECT().Add(gomock.Any(), gomock.Eq(generatedCode), gomock.Eq(validID)).Return(nil),
		emailMock.EXPECT().SendConfirmationCode(gomock.Eq(validEmail), generatedCode).Return(nil),
		codeMock.EXPECT().Get(gomock.Any(), gomock.Eq(invalidCode)).Return(int64(0), models.ErrNoRecord),
	)

	app := &application{
		config: &config{
			CodeLength:         confirmationCodeLength,
			SessionTokenLength: refreshTokenLength,
			TestAccountSuffix:  "@test.com",
		},
		logger:        zap.NewNop().Sugar(),
		users:         usersMock,
		codes:         codeMock,
		mail:          emailMock,
		jwts:          jwtMock,
		refreshTokens: refreshTokensMock,
		randSource:    &constReader{},
	}

	handler := app.route()

	signUp(t, handler)
	requestConfirm(t, handler)
	confirmInvalid(t, handler)
}

func requestConfirm(t *testing.T, h http.Handler) {
	input := struct {
		Login string `json:"login"`
	}{
		Login: validLogin,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/request_confirmation", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func confirm(t *testing.T, h http.Handler) {
	input := struct {
		Login string `json:"login"`
		Code  string `json:"code"`
	}{
		Login: validLogin,
		Code:  validCode,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/confirm", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func login(t *testing.T, h http.Handler) {
	input := struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{
		Login:    validLogin,
		Password: validPass,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	output := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  validAccessToken,
		RefreshToken: generatedRefreshToken,
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	outputJSON, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.Equal(t, outputJSON, w.Body.Bytes())
}

func requestReset(t *testing.T, h http.Handler) {
	input := struct {
		Email string `json:"email"`
	}{
		Email: validEmail,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/request_reset", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func checkReset(t *testing.T, h http.Handler) {
	input := struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}{
		Email: validEmail,
		Code:  validCode,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/check_reset_code", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func reset(t *testing.T, h http.Handler) {
	input := struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}{
		Email:    validEmail,
		Code:     validCode,
		Password: newPass,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/auth/reset", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func loginInvalidPass(t *testing.T, h http.Handler) {
	input := struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{
		Login:    validLogin,
		Password: invalidPass,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	output := invalidCredentialsBody

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	outputJSON, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.Equal(t, outputJSON, w.Body.Bytes())
}

func loginUnconfirmed(t *testing.T, h http.Handler) {
	input := struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{
		Login:    validLogin,
		Password: invalidPass,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	output := userNotConfirmedBody

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	outputJSON, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.Equal(t, outputJSON, w.Body.Bytes())
}

func confirmInvalid(t *testing.T, h http.Handler) {
	input := struct {
		Login string `json:"login"`
		Code  string `json:"code"`
	}{
		Login: validLogin,
		Code:  invalidCode,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	output := notFoundBody

	req := httptest.NewRequest("POST", "/api/v1/auth/confirm", bytes.NewBuffer(inputJSON))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	outputJSON, err := json.Marshal(output)
	assert.NoError(t, err)
	assert.Equal(t, outputJSON, w.Body.Bytes())
}
