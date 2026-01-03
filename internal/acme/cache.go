package acme

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

type DomainUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	// key          *ecdsa.PrivateKey
	key crypto.PrivateKey `json:"-"`
}

func (u *DomainUser) GetEmail() string {
	return u.Email
}
func (u DomainUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *DomainUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewDomainUser(email string, key crypto.PrivateKey) DomainUser {
	return DomainUser{
		Email: email,
		key:   key,
	}
}
