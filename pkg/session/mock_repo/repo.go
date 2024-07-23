package mock_repo

import (
	"local/auth/pkg/session"
)

type repository struct {
	db map[string]string // session id to identity
}

func New(db map[string]string) session.Repository {
	return repository{db}
}

func (r repository) Add(user_id, session_id string) {

	r.db[session_id] = user_id
}

func (r repository) Retrieve(user_id string) string {
	for k, v := range r.db {
		if v == user_id {
			return k
		}
	}
	return ""
}

func (r repository) Resolve(session_id string) string {
	for k, v := range r.db {
		if k == session_id {
			return v
		}
	}
	return ""
}

func (r repository) Delete(session_id string) {
	delete(r.db, session_id)
}
