package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	randLen = 16
	baseURL = "https://blogin.ru.com/api/v1/auth"
	code    = "TEST1"
)

func TestSignUpAndLogin(t *testing.T) {
	signUpAndLogin(t)
}

func TestResetAndLogin(t *testing.T) {
	email, username := signUpAndLogin(t)
	newPassword := randString(randLen)

	requestReset(t, email)
	checkReset(t, email)
	reset(t, email, newPassword)
	login(t, username, newPassword)
}

func TestSignUpAndIncorrectLogin(t *testing.T) {
	randStr := randString(randLen)
	email := fmt.Sprintf("%v@test.com", randStr)
	username := fmt.Sprintf("testlogin%v", randStr)
	password := randStr
	invalidPass := "invalidPass"

	signUp(t, email, username, password)
	requestConfirm(t, username)
	confirm(t, username)
	loginInvalidPass(t, username, invalidPass)
}

func TestSignUpAndUnconfirmedLogin(t *testing.T) {
	randStr := randString(randLen)
	email := fmt.Sprintf("%v@test.com", randStr)
	username := fmt.Sprintf("testlogin%v", randStr)
	password := randStr

	signUp(t, email, username, password)
	loginUnconfirmed(t, username, password)
}

func TestSignUpAndInvalidConfirmCode(t *testing.T) {
	randStr := randString(randLen)
	email := fmt.Sprintf("%v@test.com", randStr)
	username := fmt.Sprintf("testlogin%v", randStr)
	password := randStr

	signUp(t, email, username, password)
	requestConfirm(t, username)
	confirmInvalid(t, username)

	confirm(t, username)
}

func signUpAndLogin(t *testing.T) (email, username string) {
	randStr := randString(randLen)
	email = fmt.Sprintf("%v@test.com", randStr)
	username = fmt.Sprintf("testlogin%v", randStr)
	password := randStr

	signUp(t, email, username, password)
	requestConfirm(t, username)
	confirm(t, username)
	login(t, username, password)

	return
}

func signUp(t *testing.T, email, username, password string) {
	input := struct {
		FullName string `json:"full_name"`
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		FullName: "test name",
		Login:    username,
		Email:    email,
		Password: password,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/signup", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusCreated, res.StatusCode)
	assert.Empty(t, resBody)
}

func requestConfirm(t *testing.T, username string) {
	input := struct {
		Login string `json:"login"`
	}{
		Login: username,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/request_confirmation", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, resBody)
}

func confirm(t *testing.T, username string) {
	input := struct {
		Login string `json:"login"`
		Code  string `json:"code"`
	}{
		Login: username,
		Code:  code,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/confirm", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, resBody)
}

func login(t *testing.T, username string, password string) {
	input := struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{
		Login:    username,
		Password: password,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/login", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)

	output := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{}

	err = json.NewDecoder(res.Body).Decode(&output)
	assert.NoError(t, err)

	assert.NotEmpty(t, output.AccessToken)
	assert.NotEmpty(t, output.RefreshToken)
}

func requestReset(t *testing.T, email string) {
	input := struct {
		Email string `json:"email"`
	}{
		Email: email,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/request_reset", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, resBody)
}

func checkReset(t *testing.T, email string) {
	input := struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}{
		Email: email,
		Code:  code,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/check_reset_code", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, resBody)
}

func reset(t *testing.T, email, password string) {
	input := struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}{
		Email:    email,
		Code:     code,
		Password: password,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/reset", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, resBody)
}

func loginInvalidPass(t *testing.T, username, password string) {
	input := struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{
		Login:    username,
		Password: password,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/login", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	wantOutput := map[string]string{"error": "invalid credentials"}
	var output map[string]string

	err = json.NewDecoder(res.Body).Decode(&output)
	assert.NoError(t, err)

	assert.Equal(t, wantOutput, output)
}

func loginUnconfirmed(t *testing.T, username, password string) {
	input := struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}{
		Login:    username,
		Password: password,
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/login", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusForbidden, res.StatusCode)

	wantOutput := map[string]string{"error": "user not confirmed"}
	var output map[string]string

	err = json.NewDecoder(res.Body).Decode(&output)
	assert.NoError(t, err)

	assert.Equal(t, wantOutput, output)
}

func confirmInvalid(t *testing.T, username string) {
	input := struct {
		Login string `json:"login"`
		Code  string `json:"code"`
	}{
		Login: username,
		Code:  "SOMECODE",
	}

	inputJSON, err := json.Marshal(input)
	assert.NoError(t, err)

	res, err := http.Post(baseURL+"/confirm", "application/json", bytes.NewBuffer(inputJSON))
	assert.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	wantOutput := map[string]string{"error": "the requested resource could not be found"}
	var output map[string]string

	err = json.NewDecoder(res.Body).Decode(&output)
	assert.NoError(t, err)

	assert.Equal(t, wantOutput, output)
}
