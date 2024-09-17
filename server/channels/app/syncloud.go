package app

import (
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

func RegisterSyncloud(app *App) einterfaces.LdapInterface {
	return &SyncloudAuth{}
}

type SyncloudAuth struct {
}

func (s *SyncloudAuth) DoLogin(c request.CTX, id string, password string) (*model.User, *model.AppError) {
	//TODO implement me
	panic("implement me")
}

func (s *SyncloudAuth) GetUser(c request.CTX, id string) (*model.User, *model.AppError) {
	//TODO implement me
	panic("implement me")
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
