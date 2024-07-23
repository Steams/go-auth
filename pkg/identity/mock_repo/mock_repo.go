package mock_repo

import (
	"errors"
	"github.com/google/uuid"
	"local/auth/pkg/identity"
)

type EmailValidationAttempt struct {
	Code     string
	Attempts int
}

type repository struct {
	db             map[string]identity.User
	verificationDb map[string]EmailValidationAttempt
}

func New(db map[string]identity.User) identity.Repository {
	return repository{db, make(map[string]EmailValidationAttempt)}
}

func (r repository) Add(f identity.User) {
	r.db[uuid.New().String()] = f
}

func (r repository) AddVerification(email, code string) error {
	r.verificationDb[email] = EmailValidationAttempt{Code: code, Attempts: 0}
	return nil
}

func (r repository) Get(email string) (string, string, error) {
	for _, v := range r.db {
		if v.Email == email {
			return v.Email, v.Password, nil
		}
	}
	return "", "", errors.New("Email Not Found")
}

func (r repository) GetVerificationCode(email string) (string, error) {
	for k, v := range r.verificationDb {
		if k == email {
			return v.Code, nil
		}
	}
	return "", errors.New("Code Not Found")
}

func (r repository) Exists(email string) (bool, error) {
	for _, v := range r.db {
		if v.Email == email {
			return true, nil
		}
	}
	return false, nil
}

func (r repository) IdentityExists(username, email string) (bool, error) {
	for _, v := range r.db {
		if v.Email == email || v.Username == username {
			return true, nil
		}
	}
	return false, nil
}

func (r repository) IncrementVerificationAttempts(email string) error {
	for k, v := range r.verificationDb {
		if k == email {
			r.verificationDb[k] = EmailValidationAttempt{Code: v.Code, Attempts: v.Attempts + 1}
			return nil
		}
	}
	return errors.New("Code Not Found")
}

func (r repository) DeleteVerificationAttempt(email string) error {
	for k, _ := range r.verificationDb {
		if k == email {
			delete(r.verificationDb, k)
			return nil
		}
	}
	return errors.New("Code Not Found")
}

func (r repository) SetVerified(email string) error {
	for k, v := range r.db {
		if v.Email == email {
			r.db[k] = identity.User{Username: v.Username, Password: v.Password, Email: v.Email, IsVerified: true}

			return nil
		}
	}
	return errors.New("Email Not Found")
}

func (r repository) IsVerified(email string) (bool, error) {
	for _, v := range r.db {
		if v.Email == email {
			return v.IsVerified, nil
		}
	}
	return false, errors.New("Email not verified")
}
