package identity

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email      string
	Password   string
	Username   string
	IsVerified bool
}

type Repository interface {
	Add(f User)
	Get(email string) (string, string, error)
	Exists(email string) (bool, error)
	IdentityExists(username, email string) (bool, error)
	AddVerification(email, code string) error
	GetVerificationCode(email string) (string, error)
	IncrementVerificationAttempts(email string) error
	DeleteVerificationAttempt(email string) error
	SetVerified(email string) error
	IsVerified(email string) (bool, error)
}

type Service interface {
	Signup(email, password, username string, isVerified bool) error
	Login(email, password string) (string, error)
	Exists(email string) (bool, error)
	AddVerification(email, code string) error
	Verify(email, code string) (bool, error)
	IsVerified(email string) (bool, error)
}

func CreateService(r Repository) Service {
	return service_imp{r}
}

type service_imp struct {
	repo Repository
}

func (s service_imp) Exists(email string) (bool, error) {
	fmt.Println("Checking if exists")
	return s.repo.Exists(email)
}

func (s service_imp) AddVerification(email, code string) error {
	fmt.Println("Adding verification")
	return s.repo.AddVerification(email, code)
}

func (s service_imp) Signup(email, password, username string, isVerified bool) error {

	exists, err := s.repo.IdentityExists(username, email)
	if err != nil {
		fmt.Println("Error checking if email exists")
		return err
	}

	if exists {
		fmt.Println("Idenitty exists")
		return errors.New("Username or Email already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Printf("hash :", string(hash))
	s.repo.Add(User{email, string(hash), username, isVerified})
	return nil
}

func (s service_imp) Login(email, password string) (string, error) {
	email, hashedPwd, err := s.repo.Get(email)
	if err != nil {
		return "", err
	}

	verfied, err := s.repo.IsVerified(email)
	if err != nil {
		return "", err
	}

	if !verfied {
		return "", errors.New("User not verified")
	}

	fmt.Println("Email :", email)

	byteHash := []byte(hashedPwd)
	err = bcrypt.CompareHashAndPassword(byteHash, []byte(password))
	if err != nil {
		fmt.Println("Password mimatch: ", err)
		return "", err
	}

	return email, nil
}

func (s service_imp) Verify(email, code string) (bool, error) {
	storedCode, err := s.repo.GetVerificationCode(email)
	if err != nil {
		return false, errors.New("Code Not Found")
	}
	if storedCode == code {
		_ = s.repo.SetVerified(email)
		_ = s.repo.DeleteVerificationAttempt(email)
		return true, err
	}

	err = s.repo.IncrementVerificationAttempts(email)
	if err != nil {
		return false, err
	}
	// TODO if count max, delete code

	return false, nil
}

func (s service_imp) IsVerified(email string) (bool, error) {
	return s.repo.IsVerified(email)
}
