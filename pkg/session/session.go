package session

import (
	"errors"
	"local/auth/pkg/rand"
	"local/auth/pkg/utils"
	"net/url"
	"strings"
)

const (
	SECRET_KEY = "16bytesecrethere"
)

type Service interface {
	Create(user_id string) (string, string, error)
	Retrieve(user_id string) (string, error)
	Resolve(session_token string) (string, error)
	Delete(session_token string)
	Csrf(session_token string) string
	Validate(session_token, csrf_token string) bool
}

type Repository interface {
	Add(user_id, session_id string)
	Resolve(session_id string) string
	Delete(session_id string)
	Retrieve(user_id string) string
}

type service_imp struct {
	repo Repository
}

func CreateService(repo Repository) Service {
	return service_imp{repo}
}

func (s service_imp) Create(user_id string) (session_token string, csrf_token string, err error) {
	id := generate_large_random()

	s.repo.Add(user_id, id)

	token := to_token(id)
	csrfToken := to_csrf(id)

	return token, csrfToken, nil
}

func (s service_imp) Retrieve(user_id string) (string, error) {
	session_id := s.repo.Retrieve(user_id)
	if session_id == "" {
		return "", errors.New("no session")
	}

	return to_token(session_id), nil
}

func (s service_imp) Resolve(session_token string) (string, error) {
	id := from_token(session_token)

	user_id := s.repo.Resolve(id)
	if user_id == "" {
		return "", errors.New("no session")
	}
	return user_id, nil
}

// TODO this needs to vaidatte that the id actually exists first
func (s service_imp) Csrf(session_token string) string {
	return to_csrf(from_token(session_token))
}

// TODO error handling
func (s service_imp) Delete(session_token string) {
	id := from_token(session_token)

	s.repo.Delete(id)
}

func (s service_imp) Validate(session_token, csrf_token string) bool {
	return from_token(session_token) == from_token(csrf_token)
}

func to_token(session_id string) string {
	encrypted := string(utils.Encrypt([]byte("SESSION-TOKEN:"+session_id), SECRET_KEY))
	escaped := url.QueryEscape(encrypted)
	return escaped
}

func from_token(token string) string {
	unescaped, err := url.QueryUnescape(token)
	if err != nil {
		panic(err)
	}
	str, _ := utils.Decrypt([]byte(unescaped), SECRET_KEY)
	return strings.Split(string(str), ":")[1]
}

func to_csrf(session_id string) string {
	encrypted := string(utils.Encrypt([]byte("CSRF-TOKEN:"+session_id), SECRET_KEY))
	return url.QueryEscape(encrypted)
}

func generate_large_random() string {
	return rand.Hex_128()
}
