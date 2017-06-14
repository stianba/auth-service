package main

import (
	"fmt"
	"net/http"
	"os"
	"encoding/json"

	"github.com/gorilla/mux"
	"github.com/stianba/auth-service/token"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type user struct {
	ID              bson.ObjectId `json:"_id" bson:"_id,omitempty"`
	Name            string        `json:"name" bson:"name"`
	Email           string        `json:"email" bson:"email"`
	HashedPassword  []byte        `json:"-" bson:"hashedPassword"`
	PermissionLevel int           `json:"permissionLevel" bson:"permissionLevel"`
	Password        string        `json:"-" bson:",omitempty"`
}

func errorWithJSON(w http.ResponseWriter, err string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, "{\"message\": %q}", err)
}

func responseWithJSON(w http.ResponseWriter, json []byte, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(json)
}

func ensureIndex(s *mgo.Session) {
	session := s.Copy()
	defer session.Close()

	c := session.DB(os.Getenv("DB")).C("users")

	index := mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}

	err := c.EnsureIndex(index)

	if err != nil {
		panic(err)
	}
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader, ok := r.Header["Authorization"]

		if ok {
			persistentData, err := token.FromHeader(authHeader)

			if err != nil {
				errorWithJSON(w, err.Error(), http.StatusBadRequest)
				return
			}

			ctx := token.ToContext(persistentData, r)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			errorWithJSON(w, "No auth header found", http.StatusBadRequest)
		}
	})
}

func getToken(s *mgo.Session) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()

		if err != nil {
			errorWithJSON(w, "Couldn't parse request body", http.StatusBadRequest)
			return
		}

		var email, password string

		emails := r.Form["email"]
		passwords := r.Form["password"]

		if len(emails) > 0 {
			email = emails[0]
		}

		if len(passwords) > 0 {
			password = passwords[0]
		}

		if email == "" || password == "" {
			errorWithJSON(w, "Need an email and password ", http.StatusBadRequest)
			return
		}

		session := s.Copy()
		defer session.Close()

		var user user

		c := session.DB(os.Getenv("DB")).C("users")
		err = c.Find(bson.M{"email": email}).One(&user)

		if err != nil {
			errorWithJSON(w, "Couldn't find user with that email", http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)); err != nil {
			errorWithJSON(w, "Wrong password", http.StatusUnauthorized)
			return
		}

		tokenData, err := token.Generate(user.ID, user.Email, user.PermissionLevel)

		if err != nil {
			errorWithJSON(w, "Couldn't generate token", http.StatusInternalServerError)
			return
		}

		responseWithJSON(w, []byte(fmt.Sprintf("{\"message\":\"logged_in\",\"token\":\"%v\",\"expiresIn\":%d}", tokenData.TokenString, tokenData.Expires)), http.StatusOK)
	}
}

func create(s *mgo.Session) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session := s.Copy()
		defer session.Close()

		var user user

		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&user)

		if err != nil {
			errorWithJSON(w, "Incorrect body", http.StatusBadRequest)
			return
		}

		if user.Name == "" || user.Email == "" || user.Password == "" {
			errorWithJSON(w, "Missing fields", http.StatusBadRequest)
			return
		}

		if user.PermissionLevel < 1 {
			user.PermissionLevel = 1
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

		if err != nil {
			errorWithJSON(w, "Password hashing error", http.StatusInternalServerError)
			return
		}

		user.Password = ""
		user.HashedPassword = hash

		c := session.DB(os.Getenv("DB")).C("users")
		err = c.Insert(&user)

		if err != nil {
			if mgo.IsDup(err) {
				errorWithJSON(w, "User with this email already exists", http.StatusBadRequest)
				return
			}

			errorWithJSON(w, "User not inserted", http.StatusInternalServerError)
			return
		}

		responseWithJSON(w, []byte(fmt.Sprint("{\"message\":\"user_created\"}")), http.StatusOK)
	}
}

func getOne(s *mgo.Session) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		tokenData := token.GetContext(r)

		if tokenData.PermissionLevel < 2 && id != tokenData.ID {
			errorWithJSON(w, "You don't have the permissions to see other users", http.StatusForbidden)
			return
		}

		session := s.Copy()
		defer session.Close()

		var user user

		c := session.DB(os.Getenv("DB")).C("users")
		c.FindId(bson.ObjectIdHex(id)).One(&user)

		jsonData, _ := json.Marshal(user)
		responseWithJSON(w, jsonData, http.StatusOK)
	}
}

func main() {
	session, err := mgo.Dial("localhost")

	if err != nil {
		panic(err)
	}

	session.SetMode(mgo.Monotonic, true)
	ensureIndex(session)

	router := mux.NewRouter()
	router.Handle("/{id}", isAuthenticated(http.HandlerFunc(getOne(session)))).Methods("GET")
	router.HandleFunc("/", create(session)).Methods("POST")
	router.HandleFunc("/get-token", getToken(session)).Methods("POST")
	http.ListenAndServe(":1338", router)
}
