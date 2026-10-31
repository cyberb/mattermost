package oauthopenid

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
)

type OpenIdUser struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Groups            []string `json:"groups"`
}

func openIdUserFromJSON(data io.Reader) (*OpenIdUser, error) {
	var user OpenIdUser
	if err := json.NewDecoder(data).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (u *OpenIdUser) IsValid() error {
	if u.Sub == "" {
		return errors.New("user sub can't be empty")
	}
	if u.Email == "" {
		return errors.New("user e-mail should not be empty")
	}
	return nil
}

func (u *OpenIdUser) IsAdmin(group string) bool {
	return slices.Contains(u.Groups, group)
}
