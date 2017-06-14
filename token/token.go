package token

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"gopkg.in/mgo.v2/bson"
)

type userKey int

type userClaims struct {
	ID              bson.ObjectId `json:"id"`
	Email           string        `json:"email"`
	PermissionLevel int           `json:"permissionLevel"`
	jwt.StandardClaims
}

// Data is the structure of signed token string and the expiry timestamp
type Data struct {
	TokenString string
	Expires     int64
}

// UserPersistentData is data that lives through requests as context
type UserPersistentData struct {
	ID              string
	PermissionLevel float64
}

var userContextKey userKey

// Generate creates a new token and returns the signed string and expire timestamp
func Generate(id bson.ObjectId, email string, permissionLevel int) (d Data, err error) {
	expires := time.Now().Add(time.Hour * 24).Unix()

	claims := userClaims{
		id,
		email,
		permissionLevel,
		jwt.StandardClaims{
			ExpiresAt: expires,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SIGNER_SECRET")))

	if err != nil {
		return
	}

	d.TokenString = tokenString
	d.Expires = expires
	return
}

func populatePersistentObjectWithTokenData(t *jwt.Token) (u UserPersistentData, err error) {
	claims := t.Claims.(jwt.MapClaims)

	if claims["id"] == nil {
		err = fmt.Errorf("No id claim in token")
		return
	}

	if claims["permissionLevel"] == nil {
		err = fmt.Errorf("No permissionLevel claim in token")
		return
	}

	u.ID = claims["id"].(string)
	u.PermissionLevel = claims["permissionLevel"].(float64)
	return
}

// FromHeader finds auth token in header array, parses and then returns it
func FromHeader(h []string) (u UserPersistentData, err error) {
	var token string

	if len(h) > 0 {
		token = h[0]
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if token == "" {
		err = fmt.Errorf("No token found")
		return
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			msg := fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			return nil, msg
		}

		return []byte(os.Getenv("JWT_SIGNER_SECRET")), nil
	})

	if err != nil {
		return
	}

	if parsedToken != nil && parsedToken.Valid {
		u, err = populatePersistentObjectWithTokenData(parsedToken)
		return
	}

	err = fmt.Errorf("Invalid token")
	return
}

// ToContext populates context with persistent user data
func ToContext(u UserPersistentData, r *http.Request) context.Context {
	ctx := context.WithValue(r.Context(), userContextKey, u)
	return ctx
}

// GetContext returns user persistent data from context
func GetContext(r *http.Request) UserPersistentData {
	ctx := r.Context()
	u := ctx.Value(userContextKey).(UserPersistentData)
	return u
}
