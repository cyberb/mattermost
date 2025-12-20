package app

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/channels/app/users"
	"github.com/mattermost/mattermost/server/v8/channels/store"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
	"net/http"
)

func RegisterSyncloud(app *App) einterfaces.LdapInterface {
	settings := app.Config().LdapSettings
	return &SyncloudAuth{
		settings:    settings,
		userService: app.ch.srv.userService,
		url: fmt.Sprintf("%s:%d",
			*settings.LdapServer,
			*settings.LdapPort,
		),
	}
}

type SyncloudAuth struct {
	url         string
	settings    model.LdapSettings
	userService *users.UserService
}

func (s *SyncloudAuth) DoLogin(c request.CTX, id string, password string) (*model.User, *model.AppError) {
	mlog.Warn("DoLogin", mlog.String("id", id))

	user, appErr := s.GetUser(c, id)
	if appErr != nil {
		return nil, appErr
	}

	mlog.Warn("authenticate", mlog.String("id", id))
	conn, err := ldap.DialURL(s.url)
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	defer conn.Close()
	if s.settings.UsernameAttribute == nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "username attribute not set", http.StatusInternalServerError)
	}
	if s.settings.UserBaseDN == nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "user base dn not set", http.StatusInternalServerError)
	}
	err = conn.Bind(fmt.Sprintf("%s=%s,%s", *s.settings.UsernameAttribute, id, *s.settings.UserBaseDN), password)
	if err != nil {
		return nil, model.NewAppError("ldap bind", "ldap", nil, "", http.StatusUnauthorized).Wrap(err)
	}
	return user, nil
}

func (s *SyncloudAuth) GetLDAPUserForMMUser(rctx request.CTX, mmUser *model.User) (*model.User, string, *model.AppError) {
  mlog.Warn("GetLDAPUserForMMUser is not implemented yet")
  return mmUser, "", nil
}

func (s *SyncloudAuth) GetUser(c request.CTX, id string) (*model.User, *model.AppError) {
	mlog.Warn("GetUser", mlog.String("id", id))

	existingUser, err := s.userService.GetUserByAuth(&id, model.UserAuthServiceLdap)
	if err == nil {
		return existingUser, nil
	}

	var errNotFound *store.ErrNotFound
	if !errors.As(err, &errNotFound) {
		return nil, model.NewAppError("ldap", "ldap", nil, "find user error", http.StatusForbidden).Wrap(err)
	}

	conn, err := ldap.DialURL(s.url)
	if err != nil {
		mlog.Warn("dial error", mlog.Err(err))

		return nil, model.NewAppError("ldap dial", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	defer conn.Close()
	mlog.Warn("bind")
	if s.settings.BindUsername == nil || s.settings.BindPassword == nil {
		return nil, model.NewAppError("ldap bind", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	err = conn.Bind(*s.settings.BindUsername, *s.settings.BindPassword)
	if err != nil {
		mlog.Warn("bind error", mlog.Err(err))
		return nil, model.NewAppError("ldap bind", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	mlog.Warn("bound")
	if s.settings.UserFilter == nil {
		return nil, model.NewAppError("ldap user filter", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	if s.settings.UserBaseDN == nil {
		return nil, model.NewAppError("ldap user base dn", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	userSearchRequest := ldap.NewSearchRequest(
		*s.settings.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		fmt.Sprintf(*s.settings.UserFilter, id),
		[]string{"cn", "mail", "sn", "uid"},
		nil)
	mlog.Warn("search")

	sr, err := conn.Search(userSearchRequest)
	if err != nil {
		mlog.Warn("search error", mlog.Err(err))

		return nil, model.NewAppError("ldap user search", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}

	if len(sr.Entries) < 1 {
		mlog.Warn("not found")
		return nil, model.NewAppError("ldap user not found", "ldap", nil, "", http.StatusForbidden).Wrap(err)
	}
	mlog.Warn("found")
	entry := sr.Entries[0]
	emailAttribute := "mail"
	if s.settings.EmailAttribute != nil && *s.settings.EmailAttribute != "" {
		emailAttribute = *s.settings.EmailAttribute
	}
	email := entry.GetAttributeValue(emailAttribute)
	if email == "" {
		email = id + "@localhost.local"
	}
	firstNameAttribute := "cn"
	if s.settings.FirstNameAttribute != nil && *s.settings.FirstNameAttribute != "" {
		firstNameAttribute = *s.settings.FirstNameAttribute
	}

	lastNameAttribute := "sn"
	if s.settings.LastNameAttribute != nil && *s.settings.LastNameAttribute != "" {
		lastNameAttribute = *s.settings.LastNameAttribute
	}
	user := &model.User{
		Username:      id,
		AuthService:   model.UserAuthServiceLdap,
		Email:         email,
		EmailVerified: true,
		FirstName:     entry.GetAttributeValue(firstNameAttribute),
		LastName:      entry.GetAttributeValue(lastNameAttribute),
		AuthData:      &id,
	}

	mlog.Warn("admin search")
	if s.settings.AdminBaseDN == nil || s.settings.AdminFilter == nil {
		return nil, model.NewAppError("ldap admin base dn", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	adminSearchRequest := ldap.NewSearchRequest(
		*s.settings.AdminBaseDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		fmt.Sprintf(*s.settings.AdminFilter, id),
		[]string{*s.settings.GroupIdAttribute},
		nil)

	sr, err = conn.Search(adminSearchRequest)
	if err != nil {
		return nil, model.NewAppError("ldap admin search", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}

	user.Roles = model.SystemUserRoleId
	if len(sr.Entries) == 1 {
		mlog.Warn("admin")
		user.Roles = model.SystemAdminRoleId + " " + model.SystemUserRoleId
	}

	_, err = s.userService.CreateUser(c, user, users.UserCreateOptions{FromImport: true})
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "cannot add user", http.StatusForbidden).Wrap(err)
	}
	user, err = s.userService.GetUserByAuth(&id, model.UserAuthServiceLdap)
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "cannot get added user", http.StatusForbidden).Wrap(err)
	}
	return user, nil
}

func (s *SyncloudAuth) GetUserAttributes(rctx request.CTX, id string, attributes []string) (map[string]string, *model.AppError) {
	mlog.Info("GetUserAttributes not implemented")
	return make(map[string]string), nil
}

func (s *SyncloudAuth) CheckPassword(c request.CTX, id string, password string) *model.AppError {
	mlog.Info("CheckPassword not implemented")
	return nil
}

func (s *SyncloudAuth) CheckPasswordAuthData(c request.CTX, authData string, password string) *model.AppError {
	mlog.Info("CheckPasswordAuthData not implemented")
	return model.NewAppError("CheckPasswordAuthData", "ldap", nil, "CheckPasswordAuthData not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) CheckProviderAttributes(c request.CTX, LS *model.LdapSettings, ouser *model.User, patch *model.UserPatch) string {
	mlog.Info("CheckProviderAttributes not implemented")
	return ""
}

func (s *SyncloudAuth) SwitchToLdap(c request.CTX, userID, ldapID, ldapPassword string) *model.AppError {
	mlog.Info("SwitchToLdap not implemented")
	return model.NewAppError("SwitchToLdap", "ldap", nil, "SwitchToLdap not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) StartSynchronizeJob(c request.CTX, waitForJobToFinish bool) (*model.Job, *model.AppError) {
	mlog.Info("StartSynchronizeJob not implemented")
	return nil, model.NewAppError("StartSynchronizeJob", "ldap", nil, "StartSynchronizeJob not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) RunTest(rctx request.CTX) *model.AppError {
	mlog.Info("RunTest")
	conn, err := ldap.DialURL(s.url)
	if err != nil {
		return model.NewAppError("RunTest", "ldap", nil, "failed to connect to LDAP server", http.StatusInternalServerError).Wrap(err)
	}
	if err := conn.Close(); err != nil {
		return model.NewAppError("RunTest", "ldap", nil, "failed to close LDAP connection", http.StatusInternalServerError).Wrap(err)
	}
	return nil
}

func (s *SyncloudAuth) GetAllLdapUsers(c request.CTX) ([]*model.User, *model.AppError) {
	mlog.Info("GetAllLdapUsers not implemented")
	return nil, model.NewAppError("GetAllLdapUsers", "ldap", nil, "not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) MigrateIDAttribute(c request.CTX, toAttribute string) error {
	mlog.Info("MigrateIDAttribute not implemented")
	return model.NewAppError("MigrateIDAttribute", "ldap", nil, "MigrateIDAttribute not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) GetGroup(rctx request.CTX, groupUID string) (*model.Group, *model.AppError) {
	mlog.Info("GetGroup not implemented")
	return nil, model.NewAppError("GetGroup", "ldap", nil, "GetGroup not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) GetAllGroupsPage(rctx request.CTX, page int, perPage int, opts model.LdapGroupSearchOpts) ([]*model.Group, int, *model.AppError) {
	mlog.Info("GetAllGroupsPage not implemented")
	return nil, 0, model.NewAppError("GetAllGroupsPage", "ldap", nil, "not implemented", http.StatusNotImplemented)
}

func (s *SyncloudAuth) FirstLoginSync(c request.CTX, user *model.User) *model.AppError {
	mlog.Info("FirstLoginSync not implemented")
	return nil
}

func (s *SyncloudAuth) UpdateProfilePictureIfNecessary(ctx request.CTX, user model.User, session model.Session) {
	mlog.Info("UpdateProfilePictureIfNecessary not implemented")
}

func (s *SyncloudAuth) GetADLdapIdFromSAMLId(c request.CTX, authData string) string {
	mlog.Info("GetADLdapIdFromSAMLId not implemented", mlog.String("authData", authData))
	return ""
}

func (s *SyncloudAuth) GetSAMLIdFromADLdapId(c request.CTX, authData string) string {
	mlog.Info("GetSAMLIdFromADLdapId not implemented", mlog.String("authData", authData))
	return ""
}

func (s *SyncloudAuth) GetVendorNameAndVendorVersion(rctx request.CTX) (string, string, error) {
	mlog.Info("GetVendorNameAndVendorVersion not implemented")
	return "", "", nil
}
