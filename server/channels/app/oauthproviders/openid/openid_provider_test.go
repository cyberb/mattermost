package oauthopenid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

const userInfo = `{"sub":"5d1f","preferred_username":"user","email":"User@Example.com","name":"Test User","given_name":"Test","family_name":"User","groups":["users","syncloud"]}`

func TestGetUserFromJSON(t *testing.T) {
	user, err := (&OpenIdProvider{}).GetUserFromJSON(request.TestContext(t), strings.NewReader(userInfo), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "user", user.Username)
	assert.Equal(t, "user@example.com", user.Email)
	assert.Equal(t, "Test", user.FirstName)
	assert.Equal(t, "User", user.LastName)
	assert.Equal(t, "5d1f", *user.AuthData)
	assert.Equal(t, model.ServiceOpenid, user.AuthService)
	assert.False(t, user.IsSystemAdmin())
}

func TestGetUserFromJSON_AdminGroup(t *testing.T) {
	t.Setenv(AdminGroupEnv, "syncloud")
	user, err := (&OpenIdProvider{}).GetUserFromJSON(request.TestContext(t), strings.NewReader(userInfo), nil, nil)
	require.NoError(t, err)
	assert.True(t, user.IsSystemAdmin())
}

func TestGetUserFromJSON_NotInAdminGroup(t *testing.T) {
	t.Setenv(AdminGroupEnv, "admins")
	user, err := (&OpenIdProvider{}).GetUserFromJSON(request.TestContext(t), strings.NewReader(userInfo), nil, nil)
	require.NoError(t, err)
	assert.False(t, user.IsSystemAdmin())
}

func TestGetUserFromJSON_UsernameFromEmail(t *testing.T) {
	user, err := (&OpenIdProvider{}).GetUserFromJSON(request.TestContext(t), strings.NewReader(`{"sub":"1","email":"jane@example.com"}`), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "jane", user.Username)
}

func TestGetUserFromJSON_Invalid(t *testing.T) {
	_, err := (&OpenIdProvider{}).GetUserFromJSON(request.TestContext(t), strings.NewReader(`{"email":"jane@example.com"}`), nil, nil)
	assert.Error(t, err)
	_, err = (&OpenIdProvider{}).GetUserFromJSON(request.TestContext(t), strings.NewReader(`{"sub":"1"}`), nil, nil)
	assert.Error(t, err)
}

func TestIsSameUser(t *testing.T) {
	provider := &OpenIdProvider{}
	oauthUser := &model.User{Username: "user0", Email: "user@example.com", AuthData: model.NewPointer("5d1f")}
	assert.True(t, provider.IsSameUser(request.TestContext(t), &model.User{AuthService: model.UserAuthServiceLdap, Username: "user", Email: "user@example.com", AuthData: model.NewPointer("user")}, oauthUser))
	assert.False(t, provider.IsSameUser(request.TestContext(t), &model.User{AuthService: model.UserAuthServiceLdap, Email: "other@example.com"}, oauthUser))
	assert.True(t, provider.IsSameUser(request.TestContext(t), &model.User{AuthService: model.ServiceOpenid, AuthData: model.NewPointer("5d1f")}, oauthUser))
	assert.False(t, provider.IsSameUser(request.TestContext(t), &model.User{AuthService: model.ServiceOpenid, AuthData: model.NewPointer("other")}, oauthUser))
}

func TestHTTPClient(t *testing.T) {
	t.Setenv(AuthSocketEnv, "")
	assert.Nil(t, (&OpenIdProvider{}).HTTPClient())
	t.Setenv(AuthSocketEnv, "/tmp/authelia.socket")
	assert.NotNil(t, (&OpenIdProvider{}).HTTPClient())
}
