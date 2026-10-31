package oauthopenid

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

const (
	AdminGroupEnv = "MM_OPENID_ADMIN_GROUP"
	AuthSocketEnv = "MM_OPENID_AUTH_SOCKET"
)

type OpenIdProvider struct {
}

func init() {
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, &OpenIdProvider{})
}

func (p *OpenIdProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, _ *model.User, _ *model.SSOSettings) (*model.User, error) {
	oidcUser, err := openIdUserFromJSON(data)
	if err != nil {
		return nil, err
	}
	if err = oidcUser.IsValid(); err != nil {
		return nil, err
	}

	username := oidcUser.PreferredUsername
	if username == "" {
		username = strings.Split(oidcUser.Email, "@")[0]
	}

	user := &model.User{
		Username:    model.CleanUsername(rctx.Logger(), username),
		FirstName:   oidcUser.GivenName,
		LastName:    oidcUser.FamilyName,
		Email:       strings.ToLower(oidcUser.Email),
		AuthData:    model.NewPointer(oidcUser.Sub),
		AuthService: model.ServiceOpenid,
		Roles:       model.SystemUserRoleId,
	}
	if user.FirstName == "" && user.LastName == "" {
		user.FirstName = oidcUser.Name
	}
	if group := os.Getenv(AdminGroupEnv); group != "" && oidcUser.IsAdmin(group) {
		user.Roles = model.SystemAdminRoleId + " " + model.SystemUserRoleId
	}
	return user, nil
}

func (p *OpenIdProvider) GetSSOSettings(_ request.CTX, config *model.Config, _ string) (*model.SSOSettings, error) {
	return &config.OpenIdSettings, nil
}

func (p *OpenIdProvider) GetUserFromIdToken(_ request.CTX, _ string) (*model.User, error) {
	return nil, nil
}

func (p *OpenIdProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	if dbUser.AuthService == model.UserAuthServiceLdap {
		return dbUser.Email == oauthUser.Email
	}
	return model.SafeDereference(dbUser.AuthData) == model.SafeDereference(oauthUser.AuthData)
}

func (p *OpenIdProvider) HTTPClient() *http.Client {
	socket := os.Getenv(AuthSocketEnv)
	if socket == "" {
		return nil
	}
	return &http.Client{Transport: NewSocketTransport(socket), Timeout: 30 * time.Second}
}
