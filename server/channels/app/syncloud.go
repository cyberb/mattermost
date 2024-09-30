package app

import (
	"fmt"
	"github.com/mattermost/ldap"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
	"net/http"
)

func RegisterSyncloud(app *App) einterfaces.LdapInterface {
	return &SyncloudAuth{app.Config().LdapSettings}
}

type SyncloudAuth struct {
	settings model.LdapSettings
}

func (s *SyncloudAuth) DoLogin(c request.CTX, id string, password string) (*model.User, *model.AppError) {
	mlog.Warn("DoLogin", mlog.String("id", id))

	err := s.authenticate(id, password)
	if err != nil {
		return nil, model.NewAppError("ldap", "ldap", nil, "", http.StatusForbidden).Wrap(err)
	}

	return s.GetUser(c, id)
}

func (s *SyncloudAuth) authenticate(id string, password string) error {
	mlog.Warn("authenticate", mlog.String("id", id))
	conn, err := ldap.DialURL("ldap://localhost:389")
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

func (s *SyncloudAuth) GetUser(c request.CTX, id string) (*model.User, *model.AppError) {
	mlog.Warn("GetUser", mlog.String("id", id))

	conn, err := ldap.DialURL("ldap://localhost:389")
	if err != nil {
		mlog.Warn("dial error", mlog.Error(err))

		return nil, model.NewAppError("ldap dial", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}
	defer conn.Close()
	err = conn.Bind("cn=admin,dc=syncloud,dc=org", "syncloud")
	if err != nil {
		mlog.Warn("bind error", mlog.Error(err))
		return nil, model.NewAppError("ldap bind", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}

	userSearchRequest := ldap.NewSearchRequest(
		"ou=users,dc=syncloud,dc=org",
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		fmt.Sprintf("(&(objectclass=inetOrgPerson)(cn=%s))", id),
		[]string{"cn", "mail", "sn"},
		nil)

	sr, err := conn.Search(userSearchRequest)
	if err != nil {
		mlog.Warn("search error", mlog.Error(err))

		return nil, model.NewAppError("ldap user search", "ldap", nil, "", http.StatusInternalServerError).Wrap(err)
	}

	if len(sr.Entries) < 1 {
		return nil, model.NewAppError("ldap user not found", "ldap", nil, "", http.StatusForbidden).Wrap(err)
	}

	entry := sr.Entries[0]
	user := &model.User{
		AuthService:   model.UserAuthServiceLdap,
		Email:         entry.GetAttributeValue("mail"),
		EmailVerified: true,
		FirstName:     entry.GetAttributeValue("cn"),
		LastName:      entry.GetAttributeValue("sn"),
	}

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

	if len(sr.Entries) < 0 {
		user.Roles = model.SystemAdminRoleId
	}

	return user, nil
}

func (s *SyncloudAuth) GetUserAttributes(rctx request.CTX, id string, attributes []string) (map[string]string, *model.AppError) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) CheckPassword(c request.CTX, id string, password string) *model.AppError {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) CheckPasswordAuthData(c request.CTX, authData string, password string) *model.AppError {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) CheckProviderAttributes(c request.CTX, LS *model.LdapSettings, ouser *model.User, patch *model.UserPatch) string {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) SwitchToLdap(c request.CTX, userID, ldapID, ldapPassword string) *model.AppError {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) StartSynchronizeJob(c request.CTX, waitForJobToFinish bool, includeRemovedMembers bool) (*model.Job, *model.AppError) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) RunTest(rctx request.CTX) *model.AppError {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetAllLdapUsers(c request.CTX) ([]*model.User, *model.AppError) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) MigrateIDAttribute(c request.CTX, toAttribute string) error {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetGroup(rctx request.CTX, groupUID string) (*model.Group, *model.AppError) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetAllGroupsPage(rctx request.CTX, page int, perPage int, opts model.LdapGroupSearchOpts) ([]*model.Group, int, *model.AppError) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) FirstLoginSync(c request.CTX, user *model.User, userAuthService, userAuthData, email string) *model.AppError {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) UpdateProfilePictureIfNecessary(ctx request.CTX, user model.User, session model.Session) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetADLdapIdFromSAMLId(c request.CTX, authData string) string {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetSAMLIdFromADLdapId(c request.CTX, authData string) string {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetVendorNameAndVendorVersion(rctx request.CTX) (string, string, error) {
	//TODO implement me
	panic("implement me")
}
