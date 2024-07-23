package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"local/auth/pkg/identity"
	"local/auth/pkg/session"
	"math/rand"
	"time"
)

type Server interface {
	Run() error
}

type server_imp struct {
	identityService identity.Service
	sessionService  session.Service
	port            string
}

func New(i identity.Service, s session.Service, port string) Server {
	return server_imp{i, s, port}
}

func (s server_imp) Run() error {
	http.HandleFunc("/api/signup", Signup_handler(s.identityService))
	http.HandleFunc("/api/login", Login_handler(s.identityService, s.sessionService))
	http.HandleFunc("/api/logout", Logout_handler(s.sessionService))
	http.HandleFunc("/api/verify", Verify_handler(s.identityService))

	return http.ListenAndServe(":"+s.port, nil)
}

type LoginForm struct {
	Email    string
	Password string
}

type SignupForm struct {
	Email    string
	Username string
	Password string
}

type VerifyForm struct {
	Email string
	Code  string
}

type CustomClaims struct {
	Email string `json:"email"`
	Code  string `json:"code"`
	jwt.StandardClaims
}

type Error struct {
	Code    int
	Message string
}

const jwt_secret string = "mysecret"

func Login_handler(identity_service identity.Service, session_service session.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			fmt.Println("LOG: POST LOGIN Request")

			var u LoginForm
			if r.Body == nil {
				http.Error(w, "Please send a request body", 400)
				fmt.Println("LOG : No request body")
				return
			}

			err := json.NewDecoder(r.Body).Decode(&u)
			fmt.Println("login form:", u)

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				fmt.Println("LOG : Error decoding request body")
				return
			}

			// TODO this should specify the type of err
			user_id, err := identity_service.Login(u.Email, u.Password)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				fmt.Println("LOG : Log in failed:", err)
				return
			}

			var session_token string
			var csrf_token string

			session_token, err = session_service.Retrieve(user_id)

			if err != nil {
				fmt.Println("LOG : Session token does not exist. creating new session token")
				session_token, csrf_token, err = session_service.Create(user_id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					fmt.Println("LOG : Error creating session token")
					return
				}
			} else {
				fmt.Println("LOG : Session token already exists")
				csrf_token = session_service.Csrf(session_token)
			}

			cookie := http.Cookie{Name: "session_token", Value: session_token, HttpOnly: true, Path: "/"}
			http.SetCookie(w, &cookie)

			w.WriteHeader(http.StatusOK)

			js, err := json.Marshal(csrf_token)
			w.Write(js)
		}
	}
}

func Logout_handler(session_service session.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		switch r.Method {
		case "POST":
			fmt.Println("LOG: POST LOGOUT")

			cookie, err := r.Cookie("session_token")

			if err != nil {
				http.Error(w, "userid cookie not present", http.StatusBadRequest)
				return
			}

			fmt.Printf("Cookie :%s \n", cookie)
			csrf_token := r.Header.Get("Authorization")

			if csrf_token == "" {
				http.Error(w, "csrf token not present", http.StatusBadRequest)
				return
			}
			// Get the session id out of the cookie
			// How was it put in
			session_service.Delete(cookie.Value)

			http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: 0, HttpOnly: true})

			w.WriteHeader(http.StatusOK)
		}
	}
}

func Signup_handler(identity_service identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			fmt.Println("LOG : POST Signup Request")

			var form SignupForm
			if r.Body == nil {
				http.Error(w, "Please send a request body", 400)
				fmt.Println("LOG : No request body")
				return
			}

			err := json.NewDecoder(r.Body).Decode(&form)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				fmt.Println("LOG : Error decoding request body")
				return
			}

			fmt.Println("Signup: ", form)

			exists, err := identity_service.Exists(form.Email)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				fmt.Println("LOG : Error checking if account exists")
				return
			}

			if !exists {
				fmt.Println("Account does not exist")
				err = identity_service.Signup(form.Email, form.Password, form.Username, false)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					fmt.Println("LOG : Error creating account")
					return
				}
			} else {
				verified, err := identity_service.IsVerified(form.Email)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					fmt.Println("LOG : Error checking if account is verified")
					return
				}

				if verified {
					fmt.Println("Account exists and is verified")
					js, err := json.Marshal(Error{1, "Username or Email already exists"})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					w.WriteHeader(http.StatusBadRequest)
					w.Write(js)
					return
				}

				fmt.Println("Account exists but not verified")
				fmt.Println("Setting new verification code")
			}

			rand.Seed(time.Now().UnixNano())
			code := fmt.Sprintf("%06d", rand.Intn(1000000))

			claims := jwt.MapClaims{
				"email": form.Email,
				"code":  code,
				"exp":   time.Now().Add(time.Hour * 24).Unix(),
				"iat":   time.Now().Unix(),
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

			signedToken, err := token.SignedString([]byte(jwt_secret))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				fmt.Println("LOG : Error signing token")
				return
			}

			fmt.Println("Token:", signedToken)

			identity_service.AddVerification(form.Email, code)
			// send verification email
			fmt.Printf("Verification Email : Your verification code for username: %s is %s\n", form.Username, code)

			w.WriteHeader(http.StatusOK)
			return
		}
	}
}

func Verify_handler(identity_service identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Println("LOG: Verify Via Jwt token in url")

			tokenString := r.URL.Query().Get("token")
			if tokenString == "" {
				http.Error(w, "Please provide a token", 400)
				fmt.Println("LOG : No token provided")
				return
			}

			fmt.Println("Token: ", tokenString)

			token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(tokenString *jwt.Token) (interface{}, error) {
				return []byte(jwt_secret), nil
			})

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				fmt.Println("LOG : Error parsing token")
				return
			}

			if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
				fmt.Println("Claims: %+v", claims)
				verified, err := identity_service.Verify(claims.Email, claims.Code)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					fmt.Println("LOG : Error verifying code")
					return
				}

				if !verified {
					js, err := json.Marshal(Error{1, "Verification code does not match"})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					// err = identity_service.IncrementVerificationAttempts(claims.Username)
					w.WriteHeader(http.StatusBadRequest)
					w.Write(js)
					return
				}

				w.WriteHeader(http.StatusOK)
				return
			} else {
				http.Error(w, "Invalid token", http.StatusBadRequest)
				fmt.Println("LOG : Invalid token")
				return
			}

		case "POST":
			fmt.Println("LOG: POST Verify")

			var form VerifyForm
			if r.Body == nil {
				http.Error(w, "Please send a request body", 400)
				return
			}

			err := json.NewDecoder(r.Body).Decode(&form)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			fmt.Println("Verify: %+v", form)

			verified, err := identity_service.Verify(form.Email, form.Code)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if !verified {
				js, err := json.Marshal(Error{1, "Verification code does not match"})
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				w.WriteHeader(http.StatusBadRequest)
				w.Write(js)
				return
			}

			w.WriteHeader(http.StatusOK)
			return
		}
	}
}
