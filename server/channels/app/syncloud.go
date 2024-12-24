package app

import (
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
	return &SyncloudAuth{app}
}

type SyncloudAuth struct {
	app *App
}

func (s *SyncloudAuth) DoLogin(c request.CTX, id string, password string) (*model.User, *model.AppError) {
	mlog.Warn("DoLogin", mlog.String("id", id))

	user, appErr := s.GetUser(c, id)
	if appErr != nil {
		return nil, appErr
	}

	err := s.authenticate(id, password)
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "", http.StatusForbidden).Wrap(err)
	}
	return user, nil
}

func (s *SyncloudAuth) authenticate_(id string, password string) error {
	if password == "pass1234" {
		return nil
	}
	return fmt.Errorf("invalid password")
}

func (s *SyncloudAuth) authenticate(id string, password string) error {
	mlog.Warn("authenticate", mlog.String("id", id))
	url := fmt.Sprint("ldap://", *s.app.Config().LdapSettings.LdapServer, ":", *s.app.Config().LdapSettings.LdapPort)
	conn, err := ldap.DialURL(url)
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.Bind(fmt.Sprintf("cn=%s,dc=syncloud,dc=org", id), password)
	if err != nil {
		return err
	}
	return nil
}

func (s *SyncloudAuth) GetUser_(c request.CTX, id string) (*model.User, *model.AppError) {

	existingUser, err := s.app.ch.srv.userService.GetUserByAuth(&id, model.UserAuthServiceLdap)
	if err == nil {
		return existingUser, nil
	}

	if _, ok := err.(*store.ErrNotFound); !ok {
		return nil, model.NewAppError("ldap", "ldap", nil, "find user error", http.StatusForbidden).Wrap(err)
	}

	user := &model.User{
		Username:      id,
		AuthService:   model.UserAuthServiceLdap,
		Email:         "boris@example.com",
		EmailVerified: true,
		FirstName:     "boris",
		LastName:      "rybalkin",
		Roles:         model.SystemAdminRoleId,
		AuthData:      &id,
	}
	_, err = s.app.ch.srv.userService.CreateUser(c, user, users.UserCreateOptions{Guest: false})
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "cannot add user", http.StatusForbidden).Wrap(err)
	}
	user, err = s.app.ch.srv.userService.GetUserByAuth(&id, model.UserAuthServiceLdap)
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "cannot get added user", http.StatusForbidden).Wrap(err)
	}
	return user, nil
}

func (s *SyncloudAuth) GetUser(c request.CTX, id string) (*model.User, *model.AppError) {
	mlog.Warn("GetUser", mlog.String("id", id))

	existingUser, err := s.app.ch.srv.userService.GetUserByAuth(&id, model.UserAuthServiceLdap)
	if err == nil {
		return existingUser, nil
	}

	if _, ok := err.(*store.ErrNotFound); !ok {
		return nil, model.NewAppError("ldap", "ldap", nil, "find user error", http.StatusForbidden).Wrap(err)
	}

	conn, err := ldap.DialURL("ldap://localhost:389")
	if err != nil {
		mlog.Warn("dial error", mlog.Err(err))

		return nil, model.NewAppError("ldap dial", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	defer conn.Close()
	mlog.Warn("bind")
	err = conn.Bind("cn=admin,dc=syncloud,dc=org", "syncloud")
	if err != nil {
		mlog.Warn("bind error", mlog.Err(err))
		return nil, model.NewAppError("ldap bind", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	mlog.Warn("bound")
	userSearchRequest := ldap.NewSearchRequest(
		"ou=users,dc=syncloud,dc=org",
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		fmt.Sprintf("(&(objectclass=inetOrgPerson)(cn=%s))", id),
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
	user := &model.User{
		Username:      id,
		AuthService:   model.UserAuthServiceLdap,
		Email:         entry.GetAttributeValue("mail"),
		EmailVerified: true,
		FirstName:     entry.GetAttributeValue("cn"),
		LastName:      entry.GetAttributeValue("sn"),
		AuthData:      &id,
	}

	mlog.Warn("admin search")
	adminSearchRequest := ldap.NewSearchRequest(
		"cn=syncloud,ou=groups,dc=syncloud,dc=org",
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		fmt.Sprintf("(memberUid=%s)", id),
		[]string{"memberUid"},
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

	_, err = s.app.ch.srv.userService.CreateUser(c, user, users.UserCreateOptions{FromImport: true})
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "cannot add user", http.StatusForbidden).Wrap(err)
	}
	user, err = s.app.ch.srv.userService.GetUserByAuth(&id, model.UserAuthServiceLdap)
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "cannot get added user", http.StatusForbidden).Wrap(err)
	}
	return user, nil
}

func (s *SyncloudAuth) GetUserAttributes(rctx request.CTX, id string, attributes []string) (map[string]string, *model.AppError) {
	//TODO implement me
	fmt.Println("GetUserAttributes")
	panic("implement me")
}

func (s *SyncloudAuth) CheckPassword(c request.CTX, id string, password string) *model.AppError {
	//TODO implement me
	fmt.Println("CheckPassword")
	panic("implement me")
}

func (s *SyncloudAuth) CheckPasswordAuthData(c request.CTX, authData string, password string) *model.AppError {
	//TODO implement me
	fmt.Println("CheckPasswordAuthData(c")
	panic("implement me")
}

func (s *SyncloudAuth) CheckProviderAttributes(c request.CTX, LS *model.LdapSettings, ouser *model.User, patch *model.UserPatch) string {
	//TODO implement me
	fmt.Println("CheckProviderAttributes")
	panic("implement me")
}

func (s *SyncloudAuth) SwitchToLdap(c request.CTX, userID, ldapID, ldapPassword string) *model.AppError {
	//TODO implement me
	fmt.Println("SwitchToLdap")
	panic("implement me")
}

func (s *SyncloudAuth) StartSynchronizeJob(c request.CTX, waitForJobToFinish bool, includeRemovedMembers bool) (*model.Job, *model.AppError) {
	//TODO implement me
	fmt.Println("StartSynchronizeJob")
	panic("implement me")
}

func (s *SyncloudAuth) RunTest(rctx request.CTX) *model.AppError {
	//TODO implement me
	fmt.Println("RunTest")
	panic("implement me")
}

func (s *SyncloudAuth) GetAllLdapUsers(c request.CTX) ([]*model.User, *model.AppError) {
	//TODO implement me
	fmt.Println("GetAllLdapUsers")
	panic("implement me")
}

func (s *SyncloudAuth) MigrateIDAttribute(c request.CTX, toAttribute string) error {
	//TODO implement me
	fmt.Println("MigrateIDAttribute")
	panic("implement me")
}

func (s *SyncloudAuth) GetGroup(rctx request.CTX, groupUID string) (*model.Group, *model.AppError) {
	//TODO implement me
	fmt.Println("GetGroup")
	panic("implement me")
}

func (s *SyncloudAuth) GetAllGroupsPage(rctx request.CTX, page int, perPage int, opts model.LdapGroupSearchOpts) ([]*model.Group, int, *model.AppError) {
	//TODO implement me
	fmt.Println("GetAllGroupsPage")
	panic("implement me")
}

func (s *SyncloudAuth) FirstLoginSync(c request.CTX, user *model.User, userAuthService, userAuthData, email string) *model.AppError {
	//TODO implement me
	fmt.Println("FirstLoginSync")
	panic("implement me")
}

func (s *SyncloudAuth) UpdateProfilePictureIfNecessary(ctx request.CTX, user model.User, session model.Session) {
	//TODO implement me
	fmt.Println("UpdateProfilePictureIfNecessary")
	panic("implement me")
}

func (s *SyncloudAuth) GetADLdapIdFromSAMLId(c request.CTX, authData string) string {
	//TODO implement me
	fmt.Println("GetADLdapIdFromSAMLId")
	panic("implement me")
}

func (s *SyncloudAuth) GetSAMLIdFromADLdapId(c request.CTX, authData string) string {
	//TODO implement me
	fmt.Println("GetSAMLIdFromADLdapId")
	panic("implement me")
}

func (s *SyncloudAuth) GetVendorNameAndVendorVersion(rctx request.CTX) (string, string, error) {
	//TODO implement me
	fmt.Println("GetVendorNameAndVendorVersion")
	panic("implement me")
}
